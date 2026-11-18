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

#ifndef VERIFY_TESTVEC
#define VERIFY_TESTVEC sw/device/tests/acc_uov/verify_ip_testvec.h
#endif
#define TESTVEC_STR2(x) #x
#define TESTVEC_STR(x) TESTVEC_STR2(x)
#include TESTVEC_STR(VERIFY_TESTVEC)

// Streamed UOV-Ip verify driven from Ibex over TL-UL: load the app once, then
// EXECUTE per phase with the {acc, oil, target} context persisting in DMEM.
//
// This is the only route that exercises the streamed host protocol on RTL.
// acc_top_sim starts ACC once after reset and has no host bus, so it cannot
// drive INIT -> UPDATE x2 -> FINAL at all.
//
// cpk (43,576 B Ip, 46,591 B Ip3) never fits DMEM, so the host holds it and
// pushes it through in two row-aligned windows of ~22-24 KB. Note the windows top out around
// 0x58e0 - this exercises multi-execute DMEM persistence, not the 31,744 B bus
// boundary.
//
// INIT hashes msg||salt via SHAKE256 over ACC's KMAC app interface, which is
// only connected when AccPQCEn is set.
//
// Meters (meters v2, accepting run only): app_load brackets the image push;
// op_total_v2 runs from the status sentinel write to the status read; exec_wait
// sums the four EXECUTE + done polls; host_io_fold sums the input, window, ctrl
// and status transfers. Phase counts are buffered and logged after the stop.
//
// Two kernels share this host contract: the deployed streamed one and the
// swappable-backend (stream_uniform) measurement build. Every target names its
// subject via VERIFY_ARM/VERIFY_LABEL.
#ifndef VERIFY_ARM
#define VERIFY_ARM ov_Ip_verify_stream_uniform_bngfaes
#endif
#ifndef VERIFY_LABEL
#define VERIFY_LABEL "Ip stream_uniform bngfaes"
#endif
ACC_DECLARE_APP_SYMBOLS(VERIFY_ARM);
static const acc_app_t kAppSubject = ACC_APP_T_INIT(VERIFY_ARM);

// Host contract, fixed addresses (see the kernel's file header - these are not
// exported symbols). ctrl and oil sit at the same place for Ip and Ip3; sig,
// seed and the message/window base (kSigAddr, kSeedAddr, kMsgAddr) come from
// the generated header, since Ip3's 160 B sig slot moves the two above it.
enum {
  kCtrlAddr = 0x000,  // phase, arg0, arg1, status
  kOilAddr = 0x060,   // per-UPDATE host input, byte 0 = o[row_start]
};

enum { kInit = 0, kUpdate = 1, kFinal = 2 };

// o oil rows, split into two row-aligned windows. kOilCount, kSplit,
// kSplitEntry, kWindow*Bytes, kSigBytes/kSigSlot and kMsgLen all come from the
// generated header - the split must not be restated here, or the driver and the
// windows it sends can disagree.
//
// The map is triangular, so row `kSplit` starts at this many packed entries.
// Asserting it ties the three constants together: change the split without
// regenerating and this fails at compile time.
static_assert(kSplitEntry == kSplit * kOilCount - kSplit * (kSplit - 1) / 2,
              "kSplitEntry does not match kSplit/kOilCount; regenerate the header");

// The kernel's ctrl.status codes; anything else means it never wrote the word.
enum { kAccept = 0, kReject = -1, kBadPhase = -2, kSentinel = 0x5a5a5a5a };

// The message and the P3 window share 0x180: INIT consumes the message, then
// each UPDATE overwrites the region with its window. A nonzero message is
// padded to a whole 32 B block, as the ISS harness does.
static_assert(kMsgLen % 32 == 0, "message must be a whole number of 32 B blocks");
static_assert(kMsgAddr + kWindow2Bytes <= ACC_DMEM_SIZE_BYTES,
              "window 2 leaves the bus window");
static_assert(kSigBytes <= kSigSlot && kSigSlot % 4 == 0, "sig slot is written whole");
// The header's arrays must be exactly what the driver sends: a stale header
// whose byte counts drifted from its arrays would otherwise ship short windows.
static_assert(sizeof(kSigData) == kSigSlot, "kSigData is not one slot");
static_assert(sizeof(kWindow1) == kWindow1Bytes && sizeof(kWindow2) == kWindow2Bytes,
              "window arrays disagree with their byte counts");
static_assert(sizeof(kOilVec1) == 64 && sizeof(kOilVec2) == 64, "oil vectors are 64 B");

#ifndef METER_ID
#error "METER_ID comes from the BUILD target (uov_test)"
#endif

typedef struct meters {
  uint32_t acc_insn, exec_wait, host_io_fold, op_total_v2, app_load;
  uint32_t insn_total;  // kept apart from phase[] and checked against it
  uint32_t phase[4];
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

/**
 * Run one phase: stage its host writes, EXECUTE, wait.
 *
 * DMEM is not wiped by EXECUTE, so the context survives into the next phase.
 */
static void run_phase(dif_acc_t *acc, meters_t *m, int i) {
  uint64_t t0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));
  m->exec_wait += (uint32_t)(ibex_mcycle_read() - t0);
  CHECK_DIF_OK(dif_acc_get_insn_cnt(acc, &m->phase[i]));
  m->insn_total += m->phase[i];
}

static const char *const kPhaseName[4] = {"INIT", "UPDATE(head)", "UPDATE(tail)", "FINAL"};

/**
 * Drive INIT -> UPDATE x2 -> FINAL over TL-UL and return the kernel's verdict.
 *
 * `sig` is the signature to verify in its kSigSlot B slot (zero padded past
 * kSigBytes: INIT's salt read spans the whole slot); pass a corrupted copy for
 * the negative case. `total` accumulates the four phases' instruction counts.
 *
 * Loading the app does not clear DMEM - every state word the run consumes is
 * rewritten below, which is what actually keeps runs independent.
 */
static int32_t run_verify(dif_acc_t *acc, const acc_app_t app,
                          const uint8_t *sig, meters_t *m) {
  *m = (meters_t){0};
  uint64_t t_load = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_load_app(acc, app));
  m->app_load = (uint32_t)(ibex_mcycle_read() - t_load);

  // Inputs come from RAM, as from a caller: copied out of flash before the meters.
  static const uint8_t kSeedZero[32] = {0};
  UOV_IN_RAM(sig, kSigSlot);
  UOV_IN_RAM(kSeedZero, sizeof(kSeedZero));
  UOV_IN_RAM(kSeed16, sizeof(kSeed16));
  UOV_IN_RAM(kMsgData, sizeof(kMsgData));
  UOV_IN_RAM(kOilVec1, sizeof(kOilVec1));
  UOV_IN_RAM(kOilVec2, sizeof(kOilVec2));
  UOV_IN_RAM(kWindow1, kWindow1Bytes);
  UOV_IN_RAM(kWindow2, kWindow2Bytes);
  // op_total_v2: the ~45 KB of window data pushed over TL-UL between EXECUTEs
  // is inside, invisible to ACC's counter. Deltas fit 32 bits; subtract in 64
  // and narrow, because a 64-bit divide will not link on this target.
  uint64_t t_op0 = ibex_mcycle_read();

  // A fresh DMEM reads back as zero, which is also the accept code, so stamp
  // the status word first - a pass then proves the kernel actually wrote it.
  write_word(acc, kCtrlAddr + 12, kSentinel);

  // INIT: message length, signature, and the seed (cpk's first 16 B, then 16 B
  // of zero - the kernel reads a 32 B field).
  HOST_IO(m, {
    write_word(acc, kCtrlAddr, kInit);
    write_word(acc, kCtrlAddr + 4, kMsgLen);
    CHECK_STATUS_OK(acc_dmem_write(acc, kSigSlot, sig_ram, kSigAddr));
    CHECK_STATUS_OK(
        acc_dmem_write(acc, sizeof(kSeedZero), kSeedZero_ram, kSeedAddr));
    CHECK_STATUS_OK(
        acc_dmem_write(acc, sizeof(kSeed16), kSeed16_ram, kSeedAddr));
    // Consumed by INIT's SHAKE256; the first UPDATE window then overwrites it.
    // Not a preprocessor conditional: kMsgLen is an enum, so #if would see 0.
    if (kMsgLen > 0) {
      CHECK_STATUS_OK(acc_dmem_write(acc, kMsgLen, kMsgData_ram, kMsgAddr));
    }
  });
  run_phase(acc, m, 0);

  // UPDATE window 1: rows 0..kSplit-1, fed the real seed-aligned cpk prefix.
  HOST_IO(m, {
    write_word(acc, kCtrlAddr, kUpdate);
    write_word(acc, kCtrlAddr + 4, 0);
    write_word(acc, kCtrlAddr + 8, kSplit);
    CHECK_STATUS_OK(
        acc_dmem_write(acc, sizeof(kOilVec1), kOilVec1_ram, kOilAddr));
    CHECK_STATUS_OK(
        acc_dmem_write(acc, kWindow1Bytes, kWindow1_ram, kMsgAddr));
  });
  run_phase(acc, m, 1);

  // UPDATE window 2: rows kSplit..o-1, fed a dummy 16 B prefix then the rest.
  HOST_IO(m, {
    write_word(acc, kCtrlAddr, kUpdate);
    write_word(acc, kCtrlAddr + 4, kSplit);
    write_word(acc, kCtrlAddr + 8, kOilCount - kSplit);
    CHECK_STATUS_OK(
        acc_dmem_write(acc, sizeof(kOilVec2), kOilVec2_ram, kOilAddr));
    CHECK_STATUS_OK(
        acc_dmem_write(acc, kWindow2Bytes, kWindow2_ram, kMsgAddr));
  });
  run_phase(acc, m, 2);

  // FINAL: the kernel compares acc against target and writes ctrl.status.
  HOST_IO(m, write_word(acc, kCtrlAddr, kFinal));
  run_phase(acc, m, 3);

  int32_t status;
  HOST_IO(m, CHECK_STATUS_OK(acc_dmem_read(acc, sizeof(status),
                                                      kCtrlAddr + 12, &status)));
  m->op_total_v2 = (uint32_t)(ibex_mcycle_read() - t_op0);

  for (int i = 0; i < 4; ++i) {
    LOG_INFO("phase %s: %u instructions", kPhaseName[i], m->phase[i]);
    m->acc_insn += m->phase[i];
  }
  CHECK(m->acc_insn == m->insn_total, "phase counts sum to %u, running total %u",
        m->acc_insn, m->insn_total);
  CHECK(status != kSentinel, "FINAL never wrote ctrl.status");
  CHECK(status != kBadPhase, "kernel reported an invalid phase");
  return status;
}

/** Accept the KAT signature, then reject a one-byte mutation of it. */
static uint32_t verify_both_ways(dif_acc_t *acc, const acc_app_t app,
                                 const char *name, uint32_t *wall,
                                 uint32_t *acc_busy) {
  meters_t m;
  LOG_INFO("--- %s ---", name);

  int32_t status = run_verify(acc, app, kSigData, &m);
  CHECK(status == kAccept, "%s: valid signature rejected: status = %d", name,
        status);


  // One flipped signature byte must be rejected, and with the reject code
  // specifically - "nonzero" would also pass a run that mis-sequenced phases.
  uint8_t bad[kSigSlot];
  meters_t unused;
  memcpy(bad, kSigData, sizeof(bad));
  bad[0] ^= 0x10;
  status = run_verify(acc, app, bad, &unused);
  CHECK(status == kReject, "%s: corrupted signature not rejected: status = %d",
        name, status);

  LOG_INFO("%s: accepted the KAT signature, rejected a corrupted one", name);
  // The legacy "chip cycles end-to-end" bracket timed the phase logs too; its
  // successor is op_total_v2 on the meters line.
  LOG_INFO("%s: %u ACC instructions", name, m.acc_insn);
  LOG_INFO("meters v2 protocol=accept_reject " METER_ID
           " run=accept acc_insn=%u exec_wait=%u host_io_fold=%u op_total_v2=%u app_load=%u",
           m.acc_insn, m.exec_wait, m.host_io_fold, m.op_total_v2, m.app_load);
  *wall = m.op_total_v2;
  *acc_busy = m.exec_wait;
  return m.acc_insn;
}

static void test_uov_ip_verify(dif_acc_t *acc) {
  uint32_t subject_cyc = 0, subject_busy = 0;
  uint32_t fixed = verify_both_ways(acc, kAppSubject, VERIFY_LABEL, &subject_cyc, &subject_busy);
  LOG_INFO("=== UOV-Ip verify, %s, chip level ===", VERIFY_LABEL);
  LOG_INFO("  ACC instructions %u  exec+wait cycles %u", fixed, subject_busy);
}

static_assert(kDtAccCount >= 1, "This test requires at least one ACC instance");
static dt_acc_t kTestAcc = (dt_acc_t)0;

OTTF_DEFINE_TEST_CONFIG();

bool test_main(void) {
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  dif_acc_t acc;
  CHECK_DIF_OK(dif_acc_init_from_dt(kTestAcc, &acc));

  test_uov_ip_verify(&acc);

  return true;
}
