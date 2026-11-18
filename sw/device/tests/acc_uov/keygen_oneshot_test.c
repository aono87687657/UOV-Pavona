// One-shot UOV keygen driven from Ibex over TL-UL: write sk_seed, ONE EXECUTE,
// read cpk + csk. Serves every one-shot kernel (the `_min` and `_sp` families
// of Ip, Is and Ip3, all tiers): the app, the labels, the vector header and the
// geometry header (poison intervals of that ELF) come from BUILD. Seed, csk and
// cpk are addressed through the app's exported symbols.
//
// Meters follow the chip measurement contract (meters v2): app_load brackets
// the image push; op_total_v2 runs from the first transfer (the seed write) to
// the last result word read back (cpk + csk); exec_wait is EXECUTE + done poll
// (the helper's INSN_CNT/ERR_BITS reads included); the explicit INSN_CNT
// snapshot sits inside op_total_v2 but outside host_io_fold, which counts the
// two transfer brackets only (there is no fold). Comparisons and LOG_INFO come
// after the stop. One loaded image runs ONESHOT_LEGS legs (3, or 1 for the
// bnaesonly and sw tiers), each with its own meters line: seed A (accept),
// then seed B (restart_b) and seed A again (restart_a2, natural restart,
// app_load 0). Test preparation runs once and is never inside a meter: the RAM
// probe before the app load, the poison of the kernel's mutable intervals after
// it.

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

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

#ifndef KEYGEN_APP
#define KEYGEN_APP ov_Ip_keygen_sp_bngfaes
#endif
#ifndef KEYGEN_TIER
#define KEYGEN_TIER "Ip sp bngfaes"
#endif
#ifndef METER_ID
#define METER_ID "op=keygen param=ip family=sp tier=bngfaes"
#endif
// clang-format off
#ifndef KEYGEN_TESTVEC
#define KEYGEN_TESTVEC sw/device/tests/acc_uov/keygen_oneshot_ip_testvec.h
#endif
#ifndef KEYGEN_GEOM
#define KEYGEN_GEOM sw/device/tests/acc_uov/keygen_oneshot_geom_ov_Ip_keygen_sp_bngfaes.h
#endif
// clang-format on
// 3 = seed A, seed B, seed A again (A -> B -> A); 1 = the accepting run only.
#ifndef ONESHOT_LEGS
#define ONESHOT_LEGS 3
#endif
#if ONESHOT_LEGS != 1 && ONESHOT_LEGS != 3
#error "ONESHOT_LEGS must be 1 or 3"
#endif
#define ONESHOT_PROTOCOL (ONESHOT_LEGS == 3 ? "aba" : "accept_only")

#define TESTVEC_STR2(x) #x
#define TESTVEC_STR(x) TESTVEC_STR2(x)
// clang-format off
#include TESTVEC_STR(KEYGEN_TESTVEC)
#include TESTVEC_STR(KEYGEN_GEOM)
// clang-format on

ACC_DECLARE_APP_SYMBOLS(KEYGEN_APP);
static const acc_app_t kAppKeygen = ACC_APP_T_INIT(KEYGEN_APP);

// Host interface of every one-shot keygen app: seed in, csk (= the seed) and
// cpk out, addressed through the exported symbols.
ACC_DECLARE_SYMBOL_ADDR(KEYGEN_APP, sk_seed);
ACC_DECLARE_SYMBOL_ADDR(KEYGEN_APP, csk);
ACC_DECLARE_SYMBOL_ADDR(KEYGEN_APP, cpk);
static const acc_addr_t kSkSeedAddr = ACC_ADDR_T_INIT(KEYGEN_APP, sk_seed);
static const acc_addr_t kCskAddr = ACC_ADDR_T_INIT(KEYGEN_APP, csk);
static const acc_addr_t kCpkAddr = ACC_ADDR_T_INIT(KEYGEN_APP, cpk);

static_assert(kDtAccCount >= 1, "This test requires at least one ACC instance");
static dt_acc_t kTestAcc = (dt_acc_t)0;

OTTF_DEFINE_TEST_CONFIG();

enum {
  kSeedBytes = 32,
  kCpkWords = (KEYGEN_ONESHOT_CPK_LEN + 3) / 4,
  kGuardWindowWords = (KEYGEN_ONESHOT_GUARD_LEN + 3 + 4) / 4,
  kPoisonByte = 0xA5,
  // Last bus-visible DMEM word of the 128 KiB profile.
  kProbeLastWord = 130048 - 4,
};

// One buffer for every read-back: the largest cpk is 66,576 B (Is). SRAM has
// room for one of these, not two, so the expected vectors stay in flash.
static uint32_t got_cpk[kCpkWords];

typedef struct meters {
  uint32_t acc_insn;
  uint32_t exec_wait;
  uint32_t host_io;
  uint32_t op_total;
} meters_t;

/** Untimed: distinct patterns at the bottom, above 32 and 64 KiB and at the
 * last bus-visible word, read back; catches a truncated or aliased DMEM before
 * anything is loaded. Restores zeros. */
static void probe_dmem(dif_acc_t *acc) {
  static const uint32_t addrs[] = {0x0, 0x8000, 0x10000, kProbeLastWord};
  uint32_t pat[ARRAYSIZE(addrs)];
  for (size_t i = 0; i < ARRAYSIZE(addrs); ++i) {
    pat[i] = 0x5a000000u ^ (addrs[i] * 0x9e37u) ^ (uint32_t)i;
    CHECK_STATUS_OK(acc_testutils_write_data(acc, 4, &pat[i], addrs[i]));
  }
  for (size_t i = 0; i < ARRAYSIZE(addrs); ++i) {
    uint32_t got;
    CHECK_STATUS_OK(acc_testutils_read_data(acc, 4, addrs[i], &got));
    CHECK(got == pat[i], "DMEM probe at 0x%x read 0x%08x, wrote 0x%08x",
          addrs[i], got, pat[i]);
    uint32_t zero = 0;
    CHECK_STATUS_OK(acc_testutils_write_data(acc, 4, &zero, addrs[i]));
  }
  LOG_INFO("dmem probe: 4 words at 0x0/0x8000/0x10000/0x%x read back",
           kProbeLastWord);
}

/** Untimed: fill the kernel's mutable intervals with 0xA5 through the bus; a
 * partial first/last word keeps its other bytes (the `_min` guard, neighbours).
 */
static void poison(dif_acc_t *acc) {
  static uint32_t chunk[256];  // 1 KiB of poison per bus burst
  memset(chunk, kPoisonByte, sizeof(chunk));
  uint32_t total = 0;
  for (size_t k = 0; k < KEYGEN_ONESHOT_POISON_COUNT; ++k) {
    uint32_t a = kPoison[k].addr, end = kPoison[k].addr + kPoison[k].len;
    total += kPoison[k].len;
    while (a < end) {
      if ((a & 3u) != 0 || end - a < 4) {  // partial word: read-modify-write
        uint32_t wa = a & ~3u, w;
        CHECK_STATUS_OK(acc_testutils_read_data(acc, 4, wa, &w));
        uint8_t *b = (uint8_t *)&w;
        for (uint32_t x = a; x < end && x < wa + 4; ++x)
          b[x - wa] = kPoisonByte;
        CHECK_STATUS_OK(acc_testutils_write_data(acc, 4, &w, wa));
        a = wa + 4;
        continue;
      }
      uint32_t n = end - a;
      n &= ~3u;
      if (n > sizeof(chunk))
        n = sizeof(chunk);
      CHECK_STATUS_OK(acc_testutils_write_data(acc, n, chunk, a));
      a += n;
    }
  }
  LOG_INFO(
      "poison policy=named-intervals family=%s intervals=%u bytes=%u "
      "value=0x%02x",
      KEYGEN_ONESHOT_FAMILY, (unsigned)KEYGEN_ONESHOT_POISON_COUNT, total,
      kPoisonByte);
}

/** One keygen: seed in, EXECUTE, cpk + csk out; only transfers and the EXECUTE
 * inside the brackets, the INSN_CNT snapshot between them, checks after. */
static meters_t run_keygen(dif_acc_t *acc, const uint8_t *seed) {
  meters_t m;
  UOV_IN_RAM(seed, kSeedBytes);  // from RAM, as from a caller
  uint64_t t_op0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_dmem_write(acc, kSeedBytes, seed_ram, kSkSeedAddr));
  uint64_t t_e0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));
  uint64_t t_e1 = ibex_mcycle_read();
  CHECK_DIF_OK(dif_acc_get_insn_cnt(acc, &m.acc_insn));
  uint64_t t_r0 = ibex_mcycle_read();
  CHECK_STATUS_OK(
      acc_dmem_read(acc, sizeof(got_cpk), kCpkAddr, got_cpk));
  uint32_t csk[kSeedBytes / 4];
  CHECK_STATUS_OK(acc_dmem_read(acc, sizeof(csk), kCskAddr, csk));
  uint64_t t_op1 = ibex_mcycle_read();
  m.exec_wait = (uint32_t)(t_e1 - t_e0);
  m.host_io = (uint32_t)((t_e0 - t_op0) + (t_op1 - t_r0));
  m.op_total = (uint32_t)(t_op1 - t_op0);
  CHECK_ARRAYS_EQ((const uint8_t *)csk, seed, kSeedBytes);
  return m;
}

static void check_cpk(const uint8_t *expected, const char *label) {
  const uint8_t *got = (const uint8_t *)got_cpk;
  for (size_t i = 0; i < KEYGEN_ONESHOT_CPK_LEN; ++i) {
    CHECK(got[i] == expected[i],
          "%s: cpk mismatch at byte %u: 0x%02x (chip) != 0x%02x (vector)",
          label, (unsigned)i, got[i], expected[i]);
  }
}

static void check_guard(dif_acc_t *acc, const char *label) {
#if KEYGEN_ONESHOT_GUARD_LEN > 0
  // Not word aligned for every parameter set: read the aligned window that
  // covers the guard and check only its bytes (outside every meter).
  uint32_t base = kCpkAddr + KEYGEN_ONESHOT_CPK_LEN;
  uint32_t aligned = base & ~3u;
  uint32_t window[kGuardWindowWords];
  CHECK_STATUS_OK(
      acc_testutils_read_data(acc, sizeof(window), aligned, window));
  const uint8_t *w = (const uint8_t *)window + (base - aligned);
  for (size_t i = 0; i < KEYGEN_ONESHOT_GUARD_LEN; ++i) {
    CHECK(w[i] == 0, "%s: guard byte %u after cpk is 0x%02x, expected 0", label,
          (unsigned)i, w[i]);
  }
#else
  (void)acc;
  (void)label;
#endif
}

static void print_meters(const char *run, const meters_t *m,
                         uint32_t app_load) {
  LOG_INFO(
      "meters v2 protocol=%s %s run=%s acc_insn=%u exec_wait=%u "
      "host_io_fold=%u op_total_v2=%u app_load=%u",
      ONESHOT_PROTOCOL, METER_ID, run, m->acc_insn, m->exec_wait, m->host_io,
      m->op_total, app_load);
}

static void leg(dif_acc_t *acc, const uint8_t *seed, const uint8_t *expected,
                const char *label, const char *run, uint32_t app_load) {
  meters_t m = run_keygen(acc, seed);
  check_cpk(expected, label);
  check_guard(acc, label);
  LOG_INFO("oneshot keygen %s: %s cpk matches the vector (%u B)", KEYGEN_TIER,
           label, (unsigned)KEYGEN_ONESHOT_CPK_LEN);
  print_meters(run, &m, app_load);
}

bool test_main(void) {
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());
  dif_acc_t acc;
  CHECK_DIF_OK(dif_acc_init_from_dt(kTestAcc, &acc));

  probe_dmem(&acc);
  uint64_t t0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_load_app(&acc, kAppKeygen));
  uint32_t app_load = (uint32_t)(ibex_mcycle_read() - t0);
  poison(&acc);

  CHECK(memcmp(kSkSeedA, kSkSeedB, kSeedBytes) != 0,
        "seeds A and B must differ");
  leg(&acc, kSkSeedA, kCpkA, "seed A", "accept", app_load);
#if ONESHOT_LEGS == 3
  leg(&acc, kSkSeedB, kCpkB, "seed B", "restart_b", 0);
  leg(&acc, kSkSeedA, kCpkA, "seed A again", "restart_a2", 0);
  LOG_INFO("oneshot keygen %s: A -> B -> A on one loaded image", KEYGEN_TIER);
#endif
  return true;
}
