#include "hw/top/acc_regs.h"  // Generated.
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

// UOV sign (msglen 0) driven over the host TL-UL path. Inputs (sk_seed,
// msg_len, the sig slot, and the 16 B salt into salt_input) are injected over
// TL-UL after the app load, the same input path keygen and verify use. The image still carries linked copies of the same vectors, so a
// flipped-seed negative run proves the injected values are the ones consumed.
//
// The expected signature is held here rather than read back from DMEM: the
// window returns 0 while ACC is busy or locked, so comparing two values that
// both came out of the DUT can pass on all-zeroes if the wait is ever fooled.
// Meters (meters v2, accepting run): app_load brackets the image push;
// op_total_v2 runs from the first input write to the signature read-back;
// exec_wait is the EXECUTE + done poll; host_io_fold sums the input injection
// and the signature read. The stack-guard read and every comparison come after
// the stop. The negative runs are untimed.
// Tier and param come from the BUILD target. The signature depends only on the
// param - every tier computes the same value by different means - so one
// generated header serves all of a param's cells.
#ifndef SIGN_APP
#define SIGN_APP ov_Ip_sign_rtl_bngfaes_0
#endif
#ifndef SIGN_TIER
#define SIGN_TIER "Ip bngfaes"
#endif
#ifndef METER_ID
#error "METER_ID comes from the BUILD target (uov_test)"
#endif
#ifndef SIGN_TESTVEC
#define SIGN_TESTVEC sw/device/tests/acc_uov/sign_ip_testvec.h
#endif
#define SGN_STR2(x) #x
#define SGN_STR(x) SGN_STR2(x)
#include SGN_STR(SIGN_TESTVEC)

ACC_DECLARE_APP_SYMBOLS(SIGN_APP);
ACC_DECLARE_SYMBOL_ADDR(SIGN_APP, sign_s_output_addr);
ACC_DECLARE_SYMBOL_ADDR(SIGN_APP, stack_guard);
ACC_DECLARE_SYMBOL_ADDR(SIGN_APP, sk_seed);
ACC_DECLARE_SYMBOL_ADDR(SIGN_APP, msg_len);
ACC_DECLARE_SYMBOL_ADDR(SIGN_APP, sig);
ACC_DECLARE_SYMBOL_ADDR(SIGN_APP, salt_input);

static const acc_app_t kAppSign = ACC_APP_T_INIT(SIGN_APP);
static const acc_addr_t kSigOut = ACC_ADDR_T_INIT(SIGN_APP, sign_s_output_addr);
static const acc_addr_t kStackGuard = ACC_ADDR_T_INIT(SIGN_APP, stack_guard);
static const acc_addr_t kSkSeedA = ACC_ADDR_T_INIT(SIGN_APP, sk_seed);
static const acc_addr_t kMsgLenA = ACC_ADDR_T_INIT(SIGN_APP, msg_len);
static const acc_addr_t kSigA = ACC_ADDR_T_INIT(SIGN_APP, sig);
static const acc_addr_t kSaltA = ACC_ADDR_T_INIT(SIGN_APP, salt_input);

// The generator refuses nonzero msglen, and this driver writes no msg bytes.
static_assert(kMsgLen == 0, "driver handles msglen-0 vectors only");
static_assert(kSigBytes <= kSigSlot && kSigSlot % 4 == 0, "sig slot is moved whole");
static_assert(sizeof(kSigExpected) == kSigSlot, "expected sig is slot sized");
static_assert(kSigBytes >= 16, "salt is the signature's last 16 B");


static_assert(kDtAccCount >= 1, "This test requires at least one ACC instance");

static dt_acc_t kTestAcc = (dt_acc_t)0;

OTTF_DEFINE_TEST_CONFIG();

enum {
  kGuardBytes = 32,   // poison below the sign stack
  kGuardWord = 0xdeadbeef,
};

/** Write the KAT inputs over the bus from RAM; returns the Ibex cycles spent from *t_start. */
static uint32_t inject_inputs(dif_acc_t *acc, const uint8_t *seed, uint32_t salt_xor,
                              uint64_t *t_start) {
  UOV_IN_RAM(seed, sizeof(kSkSeed));
  // Writing the full expected signature into the sig slot arms the in-kernel
  // compare with the same value the host checks against. The salt is the
  // signature's last 16 B: the Ip3 kernel reads it from salt_input, while the
  // R2 harnesses re-stage salt_input from the sig slot's tail at execute time,
  // so a flipped salt is flipped in both copies to reach every kernel. Word
  // buffers throughout, because that tail is not word aligned for Ip3.
  uint32_t slot[kSigSlot / sizeof(uint32_t)];
  memcpy(slot, kSigExpected, sizeof(slot));
  uint32_t salt[4];
  memcpy(salt, kSigExpected + kSigBytes - sizeof(salt), sizeof(salt));
  salt[0] ^= salt_xor;
  memcpy((uint8_t *)slot + kSigBytes - sizeof(salt), salt, sizeof(salt));
  uint64_t t0 = *t_start = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_dmem_write(acc, sizeof(kSkSeed), seed_ram, kSkSeedA));
  uint32_t msg_len = kMsgLen;
  CHECK_STATUS_OK(acc_dmem_write(acc, sizeof(msg_len), &msg_len, kMsgLenA));
  CHECK_STATUS_OK(acc_dmem_write(acc, sizeof(slot), slot, kSigA));
  CHECK_STATUS_OK(acc_dmem_write(acc, sizeof(salt), salt, kSaltA));
  return (uint32_t)(ibex_mcycle_read() - t0);
}

/**
 * Sign one KAT message on ACC and check the signature against the vector.
 *
 * The kernel also compares in-kernel and reports via x5, but the host cannot
 * read ACC GPRs, so the verdict here is formed from DMEM alone.
 */
static void test_uov_ip_sign(dif_acc_t *acc) {
  // Brackets: app load (the image push), then op_total_v2 around input inject
  // (seed + msg_len + sig over the bus), EXECUTE + poll, and the signature read.
  uint64_t t0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_load_app(acc, kAppSign));
  uint32_t load_cycles = (uint32_t)(ibex_mcycle_read() - t0);

  uint64_t t_op0;
  uint32_t inject_cycles = inject_inputs(acc, kSkSeed, 0, &t_op0);

  t0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));
  uint32_t busy = (uint32_t)(ibex_mcycle_read() - t0);

  uint32_t got[kSigSlot / sizeof(uint32_t)];
  t0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_dmem_read(acc, sizeof(got), kSigOut, &got));
  uint64_t t_op1 = ibex_mcycle_read();
  uint32_t host_io = inject_cycles + (uint32_t)(t_op1 - t0);
  uint32_t op_total = (uint32_t)(t_op1 - t_op0);

  uint32_t guard[kGuardBytes / sizeof(uint32_t)];
  CHECK_STATUS_OK(
      acc_testutils_read_data(acc, sizeof(guard), kStackGuard, &guard));
  for (size_t i = 0; i < ARRAYSIZE(guard); ++i) {
    CHECK(guard[i] == kGuardWord,
          "Stack guard overwritten at word %d: 0x%08x != 0x%08x", i, guard[i],
          kGuardWord);
  }

  const uint8_t *got_bytes = (const uint8_t *)got;
  for (size_t i = 0; i < kSigBytes; ++i) {
    CHECK(got_bytes[i] == kSigExpected[i],
          "Signature mismatch at byte %d: 0x%02x (actual) != 0x%02x (expected)",
          i, got_bytes[i], kSigExpected[i]);
  }

  uint32_t insn_cnt;
  CHECK_DIF_OK(dif_acc_get_insn_cnt(acc, &insn_cnt));
  LOG_INFO("sign %s msglen 0: %u instructions", SIGN_TIER, insn_cnt);
  LOG_INFO("sign %s: exec+wait %u cycles, app load %u cycles, input inject %u cycles",
           SIGN_TIER, busy, load_cycles, inject_cycles);
  LOG_INFO("meters v2 protocol=accept_negative " METER_ID
           " run=accept acc_insn=%u exec_wait=%u host_io_fold=%u op_total_v2=%u app_load=%u",
           insn_cnt, busy, host_io, op_total, load_cycles);
}

/**
 * A flipped seed byte must change the signature.
 *
 * The image still carries linked copies of the same vectors, so a green run
 * alone cannot tell injected inputs from baked ones; this can.
 */
static void test_inject_negative(dif_acc_t *acc) {
  CHECK_STATUS_OK(acc_testutils_load_app(acc, kAppSign));

  uint8_t bad_seed[ARRAYSIZE(kSkSeed)];
  memcpy(bad_seed, kSkSeed, sizeof(bad_seed));
  bad_seed[0] ^= 0x10;
  inject_inputs(acc, bad_seed, 0, &(uint64_t){0});

  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));

  uint32_t got[kSigSlot / sizeof(uint32_t)];
  CHECK_STATUS_OK(acc_testutils_read_data(acc, sizeof(got), kSigOut, &got));
  CHECK(memcmp(got, kSigExpected, kSigBytes) != 0,
        "flipped sk_seed still produced the KAT signature");
  LOG_INFO("negative: flipped sk_seed changed the signature");
}

/**
 * Probe the far end of the bus window.
 *
 * The sign app only reaches ~14 KB, so signing alone never touches the top of
 * the window. Run after the signature check - this writes where the app's data
 * would be if it were larger.
 */
static void test_dmem_window_edge(dif_acc_t *acc) {
  enum { kLastWord = ACC_DMEM_SIZE_BYTES - sizeof(uint32_t) };

  static const uint32_t kPattern = 0xa5c3f00d;
  uint32_t readback = 0;

  CHECK_STATUS_OK(
      acc_testutils_write_data(acc, sizeof(kPattern), &kPattern, kLastWord));
  CHECK_STATUS_OK(
      acc_testutils_read_data(acc, sizeof(readback), kLastWord, &readback));
  CHECK(readback == kPattern,
        "Last word of the bus window did not round-trip: 0x%08x != 0x%08x",
        readback, kPattern);

  // One past the window must be refused by the DIF bounds check, not the RTL.
  uint32_t scratch = 0;
  CHECK(dif_acc_dmem_write(acc, ACC_DMEM_SIZE_BYTES, &scratch,
                           sizeof(scratch)) == kDifBadArg,
        "Write at %d should have been rejected", ACC_DMEM_SIZE_BYTES);
}

/**
 * A wrong salt must change the signature.
 *
 * The image carries the KAT salt (pre-staged in salt_input for Ip3, re-staged
 * from the sig slot by the R2 harnesses), so a green run alone cannot tell the
 * host-written salt from the linked one; this can.
 */
static void test_salt_negative(dif_acc_t *acc) {
  CHECK_STATUS_OK(acc_testutils_load_app(acc, kAppSign));
  inject_inputs(acc, kSkSeed, 0x10, &(uint64_t){0});

  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));

  uint32_t got[kSigSlot / sizeof(uint32_t)];
  CHECK_STATUS_OK(acc_testutils_read_data(acc, sizeof(got), kSigOut, &got));
  CHECK(memcmp(got, kSigExpected, kSigBytes) != 0,
        "flipped salt still produced the KAT signature");
  LOG_INFO("negative: flipped salt changed the signature");
}

bool test_main(void) {
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  dif_acc_t acc;
  CHECK_DIF_OK(dif_acc_init_from_dt(kTestAcc, &acc));

  test_uov_ip_sign(&acc);
  test_inject_negative(&acc);
  test_salt_negative(&acc);
  // Runs after the signature checks, per the comment on the probe: it writes
  // where a larger app's data would live.
  test_dmem_window_edge(&acc);

  return true;
}
