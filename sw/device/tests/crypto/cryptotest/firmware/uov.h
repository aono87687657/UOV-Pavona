// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_TESTS_CRYPTO_CRYPTOTEST_FIRMWARE_UOV_H_
#define OPENTITAN_SW_DEVICE_TESTS_CRYPTO_CRYPTOTEST_FIRMWARE_UOV_H_

#include "sw/device/lib/base/status.h"
#include "sw/device/lib/ujson/ujson.h"
#include "sw/device/tests/crypto/cryptotest/json/uov_commands.h"

// Largest cpk across the supported sets; keygen assembles it here before hashing.
#define UOV_MAX_CPK_BYTES 66576

typedef struct uov_test_scratch {
  union {
    cryptotest_uov_keygen_data_t keygen;
    cryptotest_uov_sign_data_t sign;
    cryptotest_uov_verify_data_t verify;
  } cmd;
  // Verify streams cpk in; a chunk is too big for the stack.
  cryptotest_uov_pk_chunk_t chunk;
  // Word-typed: keygen XORs entries in a word at a time.
  uint32_t cpk[UOV_MAX_CPK_BYTES / sizeof(uint32_t)];
} uov_test_scratch_t;

status_t handle_uov(ujson_t *uj, uov_test_scratch_t *s);

#endif  // OPENTITAN_SW_DEVICE_TESTS_CRYPTO_CRYPTOTEST_FIRMWARE_UOV_H_
