// One-shot UOV verify (Ip3, Ip, Is) driven from Ibex over TL-UL: the whole cpk
// resident in DMEM, one EXECUTE per verification. Serves every arm; app, labels,
// the vector header and the geometry header (hdr/sig/msg/cpk of THAT ELF) come
// from BUILD.
//
// Meters (meters v2): app_load brackets the image push (once). op_total_v2 runs
// from the status sentinel write to the status read; host_io_fold sums the
// transfers (key, msg_len, msg, sig) and the status read, the sentinel excluded;
// exec_wait is the EXECUTE + done poll; acc_insn one snapshot after it. Three
// metered runs on one loaded image, no reload or poison between them:
//   accept           key A (cpk + zero padding) + case 11 (msglen 1,024)
//   reject_resident  same inputs, signature byte 0 flipped, key resident
//   accept_resident  the original signature again, key resident
// key_load (the key transfer inside host_io_fold) is logged on its own line.
// Untimed afterwards: signature flips, length errors, non-zero padding (when the
// key has any), key corruption, key B and the cross-key check, case 0 (msglen 0);
// cpk + padding read back after every EXECUTE outside the meters; the arm's
// mutable state is poisoned (named intervals from the geometry header) only after
// the metered runs. Key B is a separate keypair with its own message when case 0
// is signed under key A (Ip3), else case 0's key (Ip, Is).

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

#ifndef VERIFY_APP
#define VERIFY_APP ov_Ip3_verify_full_bngfaes
#endif
#ifndef METER_ID
#define METER_ID "op=verify param=ip3 family=full tier=bngfaes"
#endif
#ifndef VERIFY_TESTVEC
#define VERIFY_TESTVEC sw/device/tests/acc_uov/verify_oneshot_ip3_testvec.h
#endif
#ifndef VERIFY_GEOM
#define VERIFY_GEOM sw/device/tests/acc_uov/verify_oneshot_geom_ov_Ip3_verify_full_bngfaes.h
#endif

#define TESTVEC_STR2(x) #x
#define TESTVEC_STR(x) TESTVEC_STR2(x)
#include TESTVEC_STR(VERIFY_TESTVEC)
#include TESTVEC_STR(VERIFY_GEOM)

// Ip3 check plan; the Ip and Is vector headers carry their own. Flips are
// (signature byte, mask); corruptions flip bit 0 of key bytes: pk_seed byte 3,
// byte 0 of the first and the last byte of the last P3 entry that the case-11
// signature weights (o_i * o_j != 0).
#ifndef VERIFY_ONESHOT_FLIPS
#define VERIFY_ONESHOT_FLIPS {73, 1}, {74, 1}, {100, 1}, {118, 1}, {119, 1}, {127, 1}, {134, 1}
#define VERIFY_ONESHOT_CORRUPT 3, 16, 16 + 1034 * 45 + 44
#endif
#ifndef VERIFY_ONESHOT_CASE0_KEY_B
#define VERIFY_ONESHOT_CASE0_KEY_B 0
#endif

ACC_DECLARE_APP_SYMBOLS(VERIFY_APP);
static const acc_app_t kApp = ACC_APP_T_INIT(VERIFY_APP);

static_assert(kDtAccCount >= 1, "This test requires at least one ACC instance");
static dt_acc_t kTestAcc = (dt_acc_t)0;

OTTF_DEFINE_TEST_CONFIG();

enum {
  kAccept = 0,
  kReject = -1,
  kLenError = -2,
  kSentinel = 0x5a5a5a5a,
  kKeyBytes = VERIFY_ONESHOT_KEY_BYTES,
  kChunk = 1024,
  kProbeLastWord = 130048 - 4,  // last bus-visible DMEM word of the 128 KiB profile
};
static_assert(kKeyBytes % 4 == 0 && sizeof(kKeyA) == kKeyBytes && sizeof(kKeyB) == kKeyBytes,
              "keys travel as whole words, padding included");
static_assert(VERIFY_ONESHOT_CPK_ADDR + kKeyBytes <= VERIFY_ONESHOT_DATA_END_ADDR,
              "cpk + padding must lie inside the image");

typedef struct meters {
  uint32_t acc_insn, exec_wait, host_io_fold, op_total_v2, key_load;
} meters_t;

// The key currently installed (possibly deliberately corrupted), for the
// unchanged-after-run check.
static const uint8_t *installed;
static uint8_t corrupt_key[kKeyBytes] __attribute__((aligned(4)));

static void write_word(dif_acc_t *acc, uint32_t addr, uint32_t v) {
  CHECK_STATUS_OK(acc_dmem_write(acc, 4, &v, addr));
}

/** Untimed: the resident key and padding must be exactly what was installed. */
static void check_key(dif_acc_t *acc, const char *label) {
  static uint32_t buf[kChunk / 4];
  for (uint32_t off = 0; off < kKeyBytes; off += kChunk) {
    uint32_t n = kKeyBytes - off < kChunk ? kKeyBytes - off : kChunk;
    CHECK_STATUS_OK(acc_testutils_read_data(acc, n, VERIFY_ONESHOT_CPK_ADDR + off, buf));
    CHECK(memcmp(buf, installed + off, n) == 0, "%s: resident key changed near byte %u", label,
          (unsigned)off);
  }
}

/**
 * One verification. `key` != NULL transfers the key (cpk + padding) inside the
 * meter; msg/msg_len/sig are always transferred. Returns the kernel's status.
 */
static int32_t run(dif_acc_t *acc, const uint8_t *key, const uint8_t *msg, uint32_t msg_bytes,
                   uint32_t msg_len, const uint8_t *sig, meters_t *m) {
  *m = (meters_t){0};
  int32_t status;
  uint64_t t_op0 = ibex_mcycle_read();
  write_word(acc, VERIFY_ONESHOT_HDR_ADDR + 12, kSentinel);
  uint64_t t0 = ibex_mcycle_read();
  if (key != NULL) {
    CHECK_STATUS_OK(acc_dmem_write(acc, kKeyBytes, key, VERIFY_ONESHOT_CPK_ADDR));
  }
  uint64_t t1 = ibex_mcycle_read();
  write_word(acc, VERIFY_ONESHOT_HDR_ADDR + 4, msg_len);
  if (msg_bytes > 0) {
    CHECK_STATUS_OK(acc_dmem_write(acc, msg_bytes, msg, VERIFY_ONESHOT_MSG_ADDR));
  }
  CHECK_STATUS_OK(acc_dmem_write(acc, VERIFY_ONESHOT_SIG_SLOT, sig, VERIFY_ONESHOT_SIG_ADDR));
  uint64_t t2 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_execute(acc));
  CHECK_STATUS_OK(acc_testutils_wait_for_done(acc, kDifAccErrBitsNoError));
  uint64_t t3 = ibex_mcycle_read();
  CHECK_DIF_OK(dif_acc_get_insn_cnt(acc, &m->acc_insn));
  uint64_t t4 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_dmem_read(acc, 4, VERIFY_ONESHOT_HDR_ADDR + 12, &status));
  uint64_t t_op1 = ibex_mcycle_read();
  m->key_load = key != NULL ? (uint32_t)(t1 - t0) : 0;
  m->host_io_fold = (uint32_t)((t2 - t0) + (t_op1 - t4));
  m->exec_wait = (uint32_t)(t3 - t2);
  m->op_total_v2 = (uint32_t)(t_op1 - t_op0);
  if (key != NULL) {
    installed = key;
  }
  check_key(acc, "after EXECUTE");
  CHECK(status != kSentinel, "the kernel never wrote the status word");
  return status;
}

static int32_t verify(dif_acc_t *acc, const uint8_t *key, const uint8_t *msg, uint32_t msg_bytes,
                      uint32_t msg_len, const uint8_t *sig) {
  meters_t m;
  return run(acc, key, msg, msg_bytes, msg_len, sig, &m);
}

static void expect(int32_t got, int32_t want, const char *what) {
  CHECK(got == want, "%s: status %d, want %d", what, got, want);
  LOG_INFO("ok %s: %d", what, got);
}

static void print_meters(const char *run_name, const meters_t *m, uint32_t app_load) {
  LOG_INFO("key_load run=%s cycles=%u", run_name, m->key_load);
  LOG_INFO("meters v2 protocol=verify_oneshot " METER_ID
           " run=%s acc_insn=%u exec_wait=%u host_io_fold=%u op_total_v2=%u app_load=%u",
           run_name, m->acc_insn, m->exec_wait, m->host_io_fold, m->op_total_v2, app_load);
}

/** Untimed: distinct patterns at the bottom, above 32 and 64 KiB and at the last
 * bus-visible word, read back, restored to zero; before the app load. */
static void probe_dmem(dif_acc_t *acc) {
  // All patterns first, then all reads: a smaller DMEM that mirrors high
  // addresses onto low ones overwrites an earlier pattern and fails the read.
  static const uint32_t addrs[] = {0x0, 0x8000, 0x10000, kProbeLastWord};
  uint32_t pat[ARRAYSIZE(addrs)];
  for (size_t i = 0; i < ARRAYSIZE(addrs); ++i) {
    pat[i] = 0x5a000000u ^ (addrs[i] * 0x9e37u) ^ (uint32_t)i;
    write_word(acc, addrs[i], pat[i]);
  }
  for (size_t i = 0; i < ARRAYSIZE(addrs); ++i) {
    uint32_t got;
    CHECK_STATUS_OK(acc_testutils_read_data(acc, 4, addrs[i], &got));
    CHECK(got == pat[i], "DMEM probe at 0x%x read 0x%08x, wrote 0x%08x", addrs[i], got, pat[i]);
  }
  for (size_t i = 0; i < ARRAYSIZE(addrs); ++i) {
    write_word(acc, addrs[i], 0);
  }
}

/** Untimed: 0xA5 over the arm's mutable state (context blocks, scratch) from the
 * geometry header; never the key, the message slots or the constant tables. */
static void poison(dif_acc_t *acc) {
  static uint32_t chunk[kChunk / 4];
  memset(chunk, 0xA5, sizeof(chunk));
  uint32_t total = 0;
  for (size_t k = 0; k < VERIFY_ONESHOT_POISON_COUNT; ++k) {
    for (uint32_t a = kPoison[k].addr, end = a + kPoison[k].len; a < end; a += kChunk) {
      uint32_t n = end - a < kChunk ? end - a : kChunk;
      CHECK_STATUS_OK(acc_testutils_write_data(acc, n, chunk, a));
    }
    total += kPoison[k].len;
  }
  LOG_INFO("poison 0xA5: %u intervals, %u bytes", (unsigned)VERIFY_ONESHOT_POISON_COUNT, total);
}

bool test_main(void) {
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());
  dif_acc_t acc;
  CHECK_DIF_OK(dif_acc_init_from_dt(kTestAcc, &acc));
  CHECK(memcmp(kKeyA, kKeyB, VERIFY_ONESHOT_CPK_LEN) != 0, "keys A and B must differ");

  probe_dmem(&acc);
  uint64_t t0 = ibex_mcycle_read();
  CHECK_STATUS_OK(acc_testutils_load_app(&acc, kApp));
  uint32_t app_load = (uint32_t)(ibex_mcycle_read() - t0);

  static uint8_t bad_sig[VERIFY_ONESHOT_SIG_SLOT] __attribute__((aligned(4)));
  memcpy(bad_sig, kSig11, sizeof(bad_sig));
  bad_sig[0] ^= 1;

  // Metered inputs come from RAM, as from a caller; key A reuses corrupt_key (no room for two keys).
  memcpy(corrupt_key, kKeyA, kKeyBytes);
  UOV_IN_RAM(kMsg11, sizeof(kMsg11));
  UOV_IN_RAM(kSig11, sizeof(kSig11));
  const uint8_t *msg = (const uint8_t *)kMsg11_ram, *sig = (const uint8_t *)kSig11_ram;

  // Metered: accept -> reject -> accept on one image, no reload, no poison.
  meters_t m1, m2, m3;
  int32_t s1 = run(&acc, corrupt_key, msg, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, sig, &m1);
  int32_t s2 = run(&acc, NULL, msg, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, bad_sig, &m2);
  int32_t s3 = run(&acc, NULL, msg, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, sig, &m3);
  expect(s1, kAccept, "case 11 accept (key transferred)");
  expect(s2, kReject, "case 11 reject, sig byte 0 flipped (key resident)");
  expect(s3, kAccept, "case 11 accept again (key resident)");
  print_meters("accept", &m1, app_load);
  print_meters("reject_resident", &m2, 0);
  print_meters("accept_resident", &m3, 0);

  // Untimed checks, poisoned inputs from here on.
  poison(&acc);
  expect(verify(&acc, NULL, kMsg11, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, kSig11), kAccept,
         "case 11 accept right after the poison");
  static const struct {
    uint32_t byte;
    uint32_t mask;
  } kFlips[] = {VERIFY_ONESHOT_FLIPS};
  for (size_t i = 0; i < ARRAYSIZE(kFlips); ++i) {
    memcpy(bad_sig, kSig11, sizeof(bad_sig));
    bad_sig[kFlips[i].byte] ^= (uint8_t)kFlips[i].mask;
    int32_t st = verify(&acc, NULL, kMsg11, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, bad_sig);
    CHECK(st == kReject, "sig byte %u ^ 0x%x: status %d", kFlips[i].byte, kFlips[i].mask, st);
  }
  LOG_INFO("ok %u signature flips rejected (vinegar, oil, salt and their boundaries)",
           (unsigned)ARRAYSIZE(kFlips));
  static const uint32_t kBadLens[] = {1025, 0x80000000u, 0xffffffffu};
  for (size_t i = 0; i < ARRAYSIZE(kBadLens); ++i) {
    int32_t st = verify(&acc, NULL, kMsg11, sizeof(kMsg11), kBadLens[i], kSig11);
    CHECK(st == kLenError, "msg_len 0x%x: status %d", kBadLens[i], st);
  }
  expect(verify(&acc, NULL, kMsg11, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, kSig11),
         kAccept, "accept after msg_len 1025 / 0x80000000 / 0xffffffff -> -2");

#if VERIFY_ONESHOT_KEY_BYTES > VERIFY_ONESHOT_CPK_LEN
  // Non-zero padding must not contribute.
  memcpy(corrupt_key, kKeyA, kKeyBytes);
  for (uint32_t i = VERIFY_ONESHOT_CPK_LEN; i < kKeyBytes; ++i) corrupt_key[i] = (uint8_t)(((i * 37) & 0xff) | 1);
  expect(verify(&acc, corrupt_key, kMsg11, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, kSig11),
         kAccept, "accept with non-zero P3 padding");
#else
  LOG_INFO("no padding after the cpk: no padding check");
#endif

  // A corrupted resident key rejects; the restored key accepts.
  static const uint32_t kCorrupt[] = {VERIFY_ONESHOT_CORRUPT};
  static_assert(ARRAYSIZE(kCorrupt) == 3, "pk_seed, first and last weighted P3 entry");
  for (size_t i = 0; i < ARRAYSIZE(kCorrupt); ++i) {
    memcpy(corrupt_key, kKeyA, kKeyBytes);
    corrupt_key[kCorrupt[i]] ^= 1;
    int32_t st = verify(&acc, corrupt_key, kMsg11, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, kSig11);
    CHECK(st == kReject, "key byte %u corrupted: status %d", kCorrupt[i], st);
  }
  LOG_INFO("ok key corrupted at byte %u (pk_seed) / %u / %u (first, last weighted P3 entry) rejected",
           kCorrupt[0], kCorrupt[1], kCorrupt[2]);
  expect(verify(&acc, kKeyA, kMsg11, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, kSig11),
         kAccept, "accept after the key is restored");

  // Key B: its own signature accepts; A's message + length + signature under B rejects.
#if VERIFY_ONESHOT_CASE0_KEY_B
  expect(verify(&acc, kKeyB, NULL, 0, 0, kSig0), kAccept,
         "key B accepts its own signature, case 0 (msglen 0)");
#else
  expect(verify(&acc, kKeyB, kMsgB, sizeof(kMsgB), VERIFY_ONESHOT_MSGB_LEN, kSigB), kAccept,
         "key B accepts its own signature");
#endif
  expect(verify(&acc, NULL, kMsg11, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, kSig11), kReject,
         "key A's case-11 signature under key B rejected");
  expect(verify(&acc, kKeyA, kMsg11, sizeof(kMsg11), VERIFY_ONESHOT_MSG11_LEN, kSig11),
         kAccept, "key A restored accepts");

#if VERIFY_ONESHOT_CASE0_KEY_B
  expect(verify(&acc, NULL, NULL, 0, 0, kSig0), kReject, "key B's case-0 signature under key A rejected");
#else
  // Case 0 (msglen 0) smoke.
  expect(verify(&acc, NULL, NULL, 0, 0, kSig0), kAccept, "case 0 (msglen 0) accept");
#endif
  LOG_INFO("oneshot verify %s: all checks passed", METER_ID);
  return true;
}
