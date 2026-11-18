#include "hw/top/dt/acc.h"
#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/dif/dif_acc.h"
#include "sw/device/lib/runtime/ibex.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/acc_testutils.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/tests/acc_uov/acc_dmem_copy.h"

// Param and tier are selected by the BUILD target: KEYGEN_APP names the
// acc_binary and KEYGEN_TESTVEC carries that kernel's slice geometry (o, entry
// bytes, window width). Ip and Ip3 share this driver: both pack one byte per
// oil column into 64 B slots. Defaults keep the bngfaes target buildable with
// no copts.
#ifndef KEYGEN_APP
#define KEYGEN_APP ov_Ip_keygen_stream_bngfaes
#endif
// Names itself in the log: the log IS the artifact, and a parameterised
// driver that prints a hardcoded tier misidentifies every run.
#ifndef KEYGEN_TIER
#define KEYGEN_TIER "Ip bngfaes"
#endif
#ifndef KEYGEN_TESTVEC
#define KEYGEN_TESTVEC sw/device/tests/acc_uov/keygen_stream_ip_bngfaes_testvec.h
#endif
// Stringize rather than expecting a quoted path: copts reach clang without
// shell tokenization, so embedded quotes would arrive escaped.
#define TESTVEC_STR2(x) #x
#define TESTVEC_STR(x) TESTVEC_STR2(x)
#include TESTVEC_STR(KEYGEN_TESTVEC)

// Streamed UOV-Ip keygen driven from Ibex over TL-UL: INIT once, then one
// EXECUTE per column window with the {pk_seed, aligned O} context persisting
// in DMEM.
//
// Unlike verify, this reads bulk data back between phases: each window hands
// back 44 rows x wc columns of the unfolded product M = O^T(P1*O + P2), and
// the host folds them into cpk. That read-back direction is what makes keygen untestable on acc_top_sim,
// which has no host bus at all.
//
// The fold: entry (r,c) of M belongs to cpk slot (min(r,c), max(r,c)),
// XORed in - Upper(M): mirrors merge, the diagonal arrives once and is kept. Every (r,c) arrives exactly once across the
// windows, so a zeroed buffer plus one XOR per arrival reproduces the
// reference packing without ever materialising the full 44x44 map - which
// would need 85 KB against a ~106 KB usable SRAM budget.
//
// Meters (meters v2): app_load brackets the image push; op_total_v2 runs from
// the INIT status sentinel to the last window's fold; exec_wait sums the EXECUTE
// + done polls; host_io_fold sums the seed, ctrl and status transfers, the
// pk_seed read and every window's read-back + fold. KAT comparisons and phase
// logs come after the stop.
#ifndef METER_ID
#error "METER_ID comes from the BUILD target (uov_test)"
#endif

ACC_DECLARE_APP_SYMBOLS(KEYGEN_APP);
static const acc_app_t kAppKeygen = ACC_APP_T_INIT(KEYGEN_APP);

enum {
  kCtrlAddr = 0x000,    // phase, arg0, arg1, status
  kSkSeedAddr = 0x020,  // host input, 32 B
  kPkSeedAddr = 0x040,  // INIT output, first 16 B are cpk's seed
};

enum { kInit = 0, kWindow = 1, kBadPhase = 2 };

// ctrl.status codes; anything else means the kernel never wrote the word.
enum { kStatusOk = 0, kBadArgs = -2, kSentinel = 0x5a5a5a5a };

// Geometry is per-tier and comes from the ELF via the generator, so assert the
// invariants rather than one tier's numbers: sw narrows the window to WJ=5 to
// make room for the T-table.
static_assert(kSliceAddr == 0x60, "slice moved; regenerate the test vector");
static_assert(kStride == kWj * 64, "stride must be kWj 64B slots (44B entry)");
static_assert(kWj >= 1 && kWj <= kOilDim, "window width out of range");
static_assert(kEntry == kOilDim, "GF256 geometry: one byte per oil column");
// The bus moves whole words, so an entry is read rounded up to a word (Ip3's
// 45 B entry pulls 3 pad bytes along) and only kEntry bytes are folded.
enum { kEntryRead = (kEntry + 3) & ~3u };
static_assert(kEntryRead <= kStride / kWj, "entry read spills past its slot");

// Folded upper-triangular P3, assembled here and compared against the KAT.
// Word-backed so an Ip-style entry (44 B, word multiple) still folds a word at
// a time and its measured host read-back cost does not move; an Ip3 entry
// (45 B) puts slots at non-word offsets and folds byte-wise.
static uint32_t p3_words[(kSlots * kEntry + 3) / sizeof(uint32_t)];
static uint8_t *const p3 = (uint8_t *)p3_words;
enum { kP3Bytes = kSlots * kEntry };

enum { kWindows = (kOilDim + kWj - 1) / kWj };

typedef struct meters {
  uint32_t acc_insn, exec_wait, host_io_fold, op_total_v2, app_load;
  uint32_t fold;        // read-back + fold only (legacy "host read-back")
  uint32_t insn_total;  // kept apart from phase[] and checked against it
  uint32_t phase[1 + kWindows];
} meters_t;

// Adds the Ibex cycles of `stmt` to m->host_io_fold.
#define HOST_IO(m, stmt)                                            \
  do {                                                              \
    uint64_t t_io_ = ibex_mcycle_read();                            \
    stmt;                                                           \
    (m)->host_io_fold += (uint32_t)(ibex_mcycle_read() - t_io_);    \
  } while (0)

static void write_word(dif_acc_t *acc, uint32_t addr, uint32_t value) {
  CHECK_STATUS_OK(acc_dmem_write(acc, sizeof(value), &value, addr));
}

/** Byte offset of cpk slot (a,b), a <= b, in the packed upper triangle. */
static uint32_t slot_offset(uint32_t a, uint32_t b) {
  return (a * kOilDim - a * (a - 1) / 2 + (b - a)) * kEntry;
}

/**
 * Run one phase and return its instruction count.
 *
 * Reading DMEM while ACC is busy returns zeros AND raises a fatal bus error
 * that locks the block, so every read below is sequenced after this returns.
 */
static uint32_t run_phase(dif_acc_t *acc, const char *label, uint32_t *busy,
                          uint32_t *io) {
  // Ibex-side cycles across EXECUTE + poll. INSN_CNT counts only what ACC
  // retires, so without this the read-back traffic - which dominates keygen -
  // is invisible and the cost cannot be compared against the verify cells.
  uint64_t t0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));
  *busy += (uint32_t)(ibex_mcycle_read() - t0);

  int32_t status;
  t0 = ibex_mcycle_read();
  CHECK_STATUS_OK(
      acc_dmem_read(acc, sizeof(status), kCtrlAddr + 12, &status));
  CHECK(status != kSentinel, "%s never wrote ctrl.status", label);
  CHECK(status == kStatusOk, "%s reported status %d", label, status);
  *io += (uint32_t)(ibex_mcycle_read() - t0);

  uint32_t insn_cnt;
  CHECK_DIF_OK(dif_acc_get_insn_cnt(acc, &insn_cnt));
  return insn_cnt;
}

/** Stamp the status word so "0" cannot be mistaken for a phase that never ran. */
static void arm_status(dif_acc_t *acc) {
  write_word(acc, kCtrlAddr + 12, kSentinel);
}

/** Run a WINDOW expected to be rejected, and check the status code. */
static void expect_bad_args(dif_acc_t *acc, uint32_t arg0, uint32_t arg1,
                            const char *label) {
  arm_status(acc);
  write_word(acc, kCtrlAddr, kWindow);
  write_word(acc, kCtrlAddr + 4, arg0);
  write_word(acc, kCtrlAddr + 8, arg1);
  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));

  int32_t status;
  CHECK_STATUS_OK(
      acc_testutils_read_data(acc, sizeof(status), kCtrlAddr + 12, &status));
  CHECK(status == kBadArgs, "%s gave status %d, expected %d", label, status,
        kBadArgs);
  LOG_INFO("negative: %s rejected with %d", label, status);
}


/**
 * Read one window's slice and fold it into p3.
 *
 * Only `count` columns are read: the last window is short, and reading the
 * full kWj would pull columns past kOilDim whose slot indices alias real
 * entries. The kernel zeroes the whole slice per window, so that mistake is
 * silent - hence the explicit bound plus the assertion below.
 */
static void fold_window(dif_acc_t *acc, uint32_t col_start, uint32_t count,
                        uint32_t *host) {
  uint64_t t0 = ibex_mcycle_read();
  CHECK(col_start + count <= kOilDim, "window past the last column");
  const volatile uint32_t *slice = (const volatile uint32_t *)(
      (uintptr_t)acc->base_addr.base + ACC_DMEM_REG_OFFSET + kSliceAddr);
  for (uint32_t j = 0; j < count; ++j) {
    uint32_t c = col_start + j;
    const volatile uint32_t *src = slice + j * (kStride / kWj / 4);
    // Entry (r, c) goes to slot (min, max): down column c, then along row c.
    uint32_t off = slot_offset(0, c);
    for (uint32_t r = 0; r < kOilDim; ++r, src += kStride / 4) {
      size_t w = 0;
      if (kEntry % 4 == 0) {
#pragma clang loop unroll(full)
        for (; w < kEntry / 4; ++w) {
          p3_words[off / 4 + w] ^= src[w];
        }
      } else {
        // Shift by off % 4 into aligned words; the zero bits leave neighbouring slots alone.
        uint32_t *d = &p3_words[off / 4];
        uint32_t sh = 8 * (off % 4), carry = 0;
#pragma clang loop unroll(full)
        for (; w < kEntryRead / 4; ++w) {
          uint32_t v = src[w];
          if (w == kEntryRead / 4 - 1) {
            v &= 0xffffffffu >> (8 * (kEntryRead - kEntry));  // drop the pad bytes
          }
          d[w] ^= (v << sh) | carry;
          carry = sh ? v >> (32 - sh) : 0;
        }
        if (carry) {
          d[w] ^= carry;
        }
      }
      off += (r < c ? kOilDim - r - 1 : 1) * kEntry;
    }
  }
  *host += (uint32_t)(ibex_mcycle_read() - t0);
}

static void test_uov_ip_keygen_streamed(dif_acc_t *acc) {
  meters_t m = {0};
  uint64_t t_load = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_load_app(acc, kAppKeygen));
  m.app_load = (uint32_t)(ibex_mcycle_read() - t_load);
  memset(p3_words, 0, sizeof(p3_words));

  // INIT: expand the secret seed into pk_seed plus the aligned O context.
  UOV_IN_RAM(kSkSeed, sizeof(kSkSeed));  // from RAM, as from a caller
  uint64_t t_op0 = ibex_mcycle_read();
  arm_status(acc);
  HOST_IO(&m, {
    write_word(acc, kCtrlAddr, kInit);
    CHECK_STATUS_OK(
        acc_dmem_write(acc, sizeof(kSkSeed), kSkSeed_ram, kSkSeedAddr));
  });
  m.phase[0] = run_phase(acc, "INIT", &m.exec_wait, &m.host_io_fold);
  m.insn_total += m.phase[0];

  uint8_t pk_seed[16] __attribute__((aligned(4)));
  HOST_IO(&m, CHECK_STATUS_OK(acc_dmem_read(acc, sizeof(pk_seed),
                                                       kPkSeedAddr, pk_seed)));

  // One EXECUTE per column window; fold each before starting the next, since
  // the kernel rewrites the whole slice every time.
  for (uint32_t w = 0, cs = 0; cs < kOilDim; ++w, cs += kWj) {
    uint32_t wc = (kOilDim - cs) < kWj ? (kOilDim - cs) : kWj;

    arm_status(acc);
    HOST_IO(&m, {
      write_word(acc, kCtrlAddr, kWindow);
      write_word(acc, kCtrlAddr + 4, cs);
      write_word(acc, kCtrlAddr + 8, wc);
    });
    m.phase[1 + w] = run_phase(acc, "WINDOW", &m.exec_wait, &m.host_io_fold);
    m.insn_total += m.phase[1 + w];
    fold_window(acc, cs, wc, &m.fold);
  }
  m.op_total_v2 = (uint32_t)(ibex_mcycle_read() - t_op0);
  m.host_io_fold += m.fold;
  for (uint32_t i = 0; i <= kWindows; ++i) {
    m.acc_insn += m.phase[i];
  }
  CHECK(m.acc_insn == m.insn_total, "phase counts sum to %u, running total %u",
        m.acc_insn, m.insn_total);

  LOG_INFO("phase INIT: %u instructions", m.phase[0]);
  CHECK_ARRAYS_EQ(pk_seed, kPkSeed16, ARRAYSIZE(pk_seed));
  LOG_INFO("INIT: pk_seed matches the KAT");
  for (uint32_t w = 0, cs = 0; cs < kOilDim; ++w, cs += kWj) {
    uint32_t wc = (kOilDim - cs) < kWj ? (kOilDim - cs) : kWj;
    // Check the final key slot group by slot group, in window order, so a
    // mismatch names the first window whose slots came out wrong.
    for (uint32_t b = cs; b < cs + wc; ++b) {
      for (uint32_t a = 0; a <= b; ++a) {
        uint32_t off = slot_offset(a, b);
        CHECK_ARRAYS_EQ(&p3[off], &kP3Expected[off], kEntry);
      }
    }
    LOG_INFO("WINDOW(%u,%u): %u instructions, %u slots final and correct", cs,
             wc, m.phase[1 + w], (cs + wc) * (cs + wc + 1) / 2 - cs * (cs + 1) / 2);
  }

  CHECK_ARRAYS_EQ(p3, kP3Expected, kP3Bytes);
  LOG_INFO("streamed keygen %s: cpk matches the KAT (%u B packed P3)",
           KEYGEN_TIER, (uint32_t)kP3Bytes);
  LOG_INFO("tier %s: exec+wait %u cycles, host read-back %u cycles",
           KEYGEN_TIER, m.exec_wait, m.fold);
  LOG_INFO("meters v2 protocol=accept_only " METER_ID
           " run=accept acc_insn=%u exec_wait=%u host_io_fold=%u op_total_v2=%u app_load=%u",
           m.acc_insn, m.exec_wait, m.host_io_fold, m.op_total_v2, m.app_load);
}

/** Cheap negatives: the kernel must reject a bad phase and react to the seed. */
static void test_negatives(dif_acc_t *acc) {
  CHECK_STATUS_OK(acc_testutils_load_app(acc, kAppKeygen));

  arm_status(acc);
  write_word(acc, kCtrlAddr, kBadPhase);
  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));

  int32_t status;
  CHECK_STATUS_OK(
      acc_testutils_read_data(acc, sizeof(status), kCtrlAddr + 12, &status));
  CHECK(status == kBadArgs, "bad phase gave status %d, expected %d", status,
        kBadArgs);
  LOG_INFO("negative: invalid phase rejected with %d", status);

  // Window bounds. The kernel rejects rather than truncating, so a host that
  // asks for a window it cannot have gets an error, not a plausible wrong cpk.
  // Ip/Ip3 take any col_count 1..kWj - unlike Is there is no even-only rule.
  expect_bad_args(acc, 0, 0, "col_count = 0");
  expect_bad_args(acc, 0, kWj + 1, "col_count > kWj");
  expect_bad_args(acc, kOilDim, 1, "col_start >= kOilDim");
  expect_bad_args(acc, kOilDim - 1, kWj, "col_start + col_count > kOilDim");

  // A flipped seed byte must change pk_seed - proves INIT derives it rather
  // than returning something baked in.
  uint8_t bad_seed[sizeof(kSkSeed)];
  memcpy(bad_seed, kSkSeed, sizeof(bad_seed));
  bad_seed[0] ^= 0x10;

  arm_status(acc);
  write_word(acc, kCtrlAddr, kInit);
  CHECK_STATUS_OK(
      acc_testutils_write_data(acc, sizeof(bad_seed), bad_seed, kSkSeedAddr));
  uint32_t discard = 0, discard_io = 0;
  run_phase(acc, "INIT (flipped seed)", &discard, &discard_io);

  uint8_t pk_seed[16];
  CHECK_STATUS_OK(
      acc_testutils_read_data(acc, sizeof(pk_seed), kPkSeedAddr, pk_seed));
  CHECK(memcmp(pk_seed, kPkSeed16, sizeof(pk_seed)) != 0,
        "flipped sk_seed produced the same pk_seed");
  LOG_INFO("negative: flipped sk_seed changed pk_seed");
}

static_assert(kDtAccCount >= 1, "This test requires at least one ACC instance");
static dt_acc_t kTestAcc = (dt_acc_t)0;

OTTF_DEFINE_TEST_CONFIG();

bool test_main(void) {
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  dif_acc_t acc;
  CHECK_DIF_OK(dif_acc_init_from_dt(kTestAcc, &acc));

  test_uov_ip_keygen_streamed(&acc);
  test_negatives(&acc);

  return true;
}
