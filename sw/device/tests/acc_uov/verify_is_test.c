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

// Window schedule is bounded by the target's winend-msgwin, so the stream_uniform
// arms need their own header: they link backend .data straight after winend,
// where the deployed kernel has none.
#ifndef VERIFY_TESTVEC
#define VERIFY_TESTVEC sw/device/tests/acc_uov/verify_stream_is_testvec.h
#endif
#define VTV_STR2(x) #x
#define VTV_STR(x) VTV_STR2(x)
#include VTV_STR(VERIFY_TESTVEC)

// Streamed UOV-Is verify driven from Ibex over TL-UL.
//
// Is is not a relabelled Ip: different DMEM layout, GF16 nibble-packed 32 B
// entries, and three windows rather than two - 2,080 entries at 32 B is
// 66,560 B, which no pair of windows can carry through a 31,744 B bus window.
// That makes this the only chip-level case exercising K>2 streaming.
//
// The per-window oil vector is nibble-aligned (shifted by 4*row_start), so the
// generator emits one pre-shifted vector per window and this driver only
// writes bytes.
//
// Meters (meters v2, accepting run only): app_load brackets the image push;
// op_total_v2 runs from the status sentinel write to the final status read;
// exec_wait sums the EXECUTE + done polls; host_io_fold sums the input, window,
// ctrl and per-phase status transfers. Phase counts are logged after the stop.
// Tier comes from the BUILD target; the default is the deployed streamed kernel.
#ifndef VERIFY_ARM
#define VERIFY_ARM ov_Is_verify_stream_bngfaes
#endif
#ifndef VERIFY_LABEL
#define VERIFY_LABEL "Is streamed bngfaes (deployed)"
#endif

ACC_DECLARE_APP_SYMBOLS(VERIFY_ARM);
static const acc_app_t kAppIs = ACC_APP_T_INIT(VERIFY_ARM);

// Is host contract - every offset differs from Ip.
enum {
  kCtrlAddr = 0x000,    // phase, arg0, arg1, status
  kAccAddr = 0x020,     // 32 B
  kOilAddr = 0x040,     // per-UPDATE, nibble-aligned to row_start
  kTargetAddr = 0x060,  // 32 B
  kSigAddr = 0x080,     // 96 B
  kSeedAddr = 0x0E0,    // 16 B seed + 16 B pad
  kMsgAddr = 0x100,     // message, then each window's P3 slice (no prefix)
};

enum { kInit = 0, kUpdate = 1, kFinal = 2 };
enum {
  kAccept = 0,
  kReject = -1,
  kBadPhase = -2,   // also: UPDATE argument/capacity rejection
  kNoInit = -3,     // stream_uniform only: UPDATE/FINAL before INIT
  kSentinel = 0x5a5a5a5a,
};

static_assert(kIsOilCount == 64 && kIsEntry == 32, "Is geometry moved");
static_assert(kIsWindows >= 3, "Is cannot stream in fewer than three windows");
static_assert(kIsMsgLen % 32 == 0, "message must be whole 32 B blocks");

static const uint8_t *const kIsOil[] = {kIsOil0, kIsOil1, kIsOil2};
static const uint8_t *const kIsWindow[] = {kIsWindow0, kIsWindow1, kIsWindow2};
static_assert(ARRAYSIZE(kIsOil) == kIsWindows, "oil vector count mismatch");
static_assert(ARRAYSIZE(kIsWindow) == kIsWindows, "window count mismatch");

#ifndef METER_ID
#error "METER_ID comes from the BUILD target (uov_test)"
#endif

enum { kIsPhases = kIsWindows + 2 };

typedef struct meters {
  uint32_t acc_insn, exec_wait, host_io_fold, op_total_v2, app_load;
  uint32_t insn_total;  // kept apart from phase[] and checked against it
  uint32_t phase[kIsPhases];
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

static void run_phase(dif_acc_t *acc, meters_t *m, int i, const char *label) {
  // Ibex-side cycles across EXECUTE + poll, accumulated before the status read
  // below so Is cells don't carry a per-phase TL-UL read the Ip cells lack.
  uint64_t t0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));
  m->exec_wait += (uint32_t)(ibex_mcycle_read() - t0);

  // Check every phase, not just FINAL. An UPDATE that rejects its arguments
  // writes -2 here and returns in ~35 instructions; without this the run
  // continues and FINAL reports -1, which reads as a bad signature rather than
  // a bad window. That cost a chip run to diagnose.
  int32_t status;
  HOST_IO(m, {
    CHECK_STATUS_OK(
        acc_dmem_read(acc, sizeof(status), kCtrlAddr + 12, &status));
    CHECK(status != kBadPhase && status != kNoInit,
          "%s rejected its arguments: status = %d", label, status);
  });
  CHECK_DIF_OK(dif_acc_get_insn_cnt(acc, &m->phase[i]));
  m->insn_total += m->phase[i];
}

/** INIT -> UPDATE x kIsWindows -> FINAL; returns the kernel's verdict. */
static int32_t run_verify(dif_acc_t *acc, const uint8_t *sig, meters_t *m) {
  *m = (meters_t){0};
  uint64_t t_load = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_load_app(acc, kAppIs));
  m->app_load = (uint32_t)(ibex_mcycle_read() - t_load);

  // Inputs come from RAM, as from a caller: copied out of flash before the meters.
  UOV_IN_RAM(sig, sizeof(kIsSig));
  UOV_IN_RAM(kIsSeed32, sizeof(kIsSeed32));
  UOV_IN_RAM(kIsMsgData, sizeof(kIsMsgData));
  static uint32_t oil_ram[kIsWindows][8];
  static uint32_t window_ram[(sizeof(kIsWindow0) + sizeof(kIsWindow1) + sizeof(kIsWindow2)) / 4];
  const uint32_t *win_ram[kIsWindows];
  for (uint32_t w = 0, off = 0; w < kIsWindows; off += kIsSched[w][2] / 4, ++w) {
    memcpy(oil_ram[w], kIsOil[w], sizeof(oil_ram[w]));
    win_ram[w] = memcpy(&window_ram[off], kIsWindow[w], kIsSched[w][2]);
  }
  uint64_t t_op0 = ibex_mcycle_read();
  // Fresh DMEM reads as zero, which is also the accept code.
  write_word(acc, kCtrlAddr + 12, kSentinel);

  HOST_IO(m, {
    write_word(acc, kCtrlAddr, kInit);
    write_word(acc, kCtrlAddr + 4, kIsMsgLen);
    CHECK_STATUS_OK(acc_dmem_write(acc, sizeof(kIsSig), sig_ram, kSigAddr));
    CHECK_STATUS_OK(
        acc_dmem_write(acc, sizeof(kIsSeed32), kIsSeed32_ram, kSeedAddr));
    if (kIsMsgLen > 0) {
      CHECK_STATUS_OK(
          acc_dmem_write(acc, kIsMsgLen, kIsMsgData_ram, kMsgAddr));
    }
  });
  run_phase(acc, m, 0, "INIT");

  for (uint32_t w = 0; w < kIsWindows; ++w) {
    uint32_t row_start = kIsSched[w][0];
    uint32_t row_count = kIsSched[w][1];
    uint32_t bytes = kIsSched[w][2];
    CHECK(kMsgAddr + bytes <= ACC_DMEM_SIZE_BYTES,
          "window %u leaves the bus window", w);

    HOST_IO(m, {
      write_word(acc, kCtrlAddr, kUpdate);
      write_word(acc, kCtrlAddr + 4, row_start);
      write_word(acc, kCtrlAddr + 8, row_count);
      CHECK_STATUS_OK(acc_dmem_write(acc, 32, oil_ram[w], kOilAddr));
      CHECK_STATUS_OK(
          acc_dmem_write(acc, bytes, win_ram[w], kMsgAddr));
    });
    run_phase(acc, m, 1 + (int)w, "UPDATE");
  }

  HOST_IO(m, write_word(acc, kCtrlAddr, kFinal));
  run_phase(acc, m, kIsPhases - 1, "FINAL");

  int32_t status;
  HOST_IO(m, CHECK_STATUS_OK(acc_dmem_read(acc, sizeof(status),
                                                      kCtrlAddr + 12, &status)));
  m->op_total_v2 = (uint32_t)(ibex_mcycle_read() - t_op0);

  for (int i = 0; i < kIsPhases; ++i) {
    LOG_INFO("phase %s: %u instructions",
             i == 0 ? "INIT" : i == kIsPhases - 1 ? "FINAL" : "UPDATE", m->phase[i]);
    m->acc_insn += m->phase[i];
  }
  CHECK(m->acc_insn == m->insn_total, "phase counts sum to %u, running total %u",
        m->acc_insn, m->insn_total);
  CHECK(status != kSentinel, "FINAL never wrote ctrl.status");
  CHECK(status != kBadPhase, "kernel reported an invalid phase");
  return status;
}

static void test_uov_is_verify_streamed(dif_acc_t *acc) {
  meters_t m, unused;

  int32_t status = run_verify(acc, kIsSig, &m);
  CHECK(status == kAccept, "valid signature rejected: status = %d", status);
  LOG_INFO("UOV-Is streamed verify: %u windows over TL-UL, signature accepted",
           (uint32_t)kIsWindows);
  LOG_INFO("UOV-Is: %u ACC instructions, exec+wait %u cycles for the accepting run",
           m.acc_insn, m.exec_wait);
  LOG_INFO("meters v2 protocol=accept_reject " METER_ID
           " run=accept acc_insn=%u exec_wait=%u host_io_fold=%u op_total_v2=%u app_load=%u",
           m.acc_insn, m.exec_wait, m.host_io_fold, m.op_total_v2, m.app_load);

  uint8_t bad[sizeof(kIsSig)];
  memcpy(bad, kIsSig, sizeof(bad));
  bad[0] ^= 0x10;
  status = run_verify(acc, bad, &unused);
  CHECK(status == kReject, "corrupted signature not rejected: status = %d",
        status);
  LOG_INFO("UOV-Is streamed verify: corrupted signature rejected");
}

static_assert(kDtAccCount >= 1, "This test requires at least one ACC instance");
static dt_acc_t kTestAcc = (dt_acc_t)0;

OTTF_DEFINE_TEST_CONFIG();

bool test_main(void) {
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  dif_acc_t acc;
  CHECK_DIF_OK(dif_acc_init_from_dt(kTestAcc, &acc));

  test_uov_is_verify_streamed(&acc);

  return true;
}
