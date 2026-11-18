// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_TESTS_CRYPTO_CRYPTOTEST_JSON_UOV_COMMANDS_H_
#define OPENTITAN_SW_DEVICE_TESTS_CRYPTO_CRYPTOTEST_JSON_UOV_COMMANDS_H_
#include "sw/device/lib/ujson/ujson_derive.h"
#ifdef __cplusplus
extern "C" {
#endif

#define MODULE_ID MAKE_MODULE_ID('j', 'u', 'v')

#define UOV_CMD_MAX_SEED_BYTES 32
#define UOV_CMD_MAX_SALT_BYTES 16
#define UOV_CMD_MAX_MSG_BYTES 3300  // pqov KAT: mlen = 33*100
#define UOV_CMD_MAX_SIG_BYTES 160  // Ip3: 135 B in a 160 B slot
// Public keys are tens of KB, so verify streams them in chunks.
#define UOV_CMD_MAX_PK_CHUNK_BYTES 2048
#define UOV_CMD_HASH_BYTES 32

// clang-format off

#define UOV_SUBCOMMAND(_, value) \
    value(_, UovKeygen) \
    value(_, UovSign) \
    value(_, UovVerify)
UJSON_SERDE_ENUM(UovSubcommand, uov_subcommand_t, UOV_SUBCOMMAND);

#define UOV_PARAM(_, value) \
    value(_, UovIp) \
    value(_, UovIs) \
    value(_, UovIp3)
UJSON_SERDE_ENUM(UovParam, uov_param_t, UOV_PARAM);

// Keygen: seed in, SHA3-256(cpk) out.
#define UOV_KEYGEN_DATA(field, string) \
    field(parameter_set, uint32_t) \
    field(sk_seed, uint8_t, UOV_CMD_MAX_SEED_BYTES) \
    field(sk_seed_len, size_t)
UJSON_SERDE_STRUCT(CryptotestUovKeygenData, cryptotest_uov_keygen_data_t, UOV_KEYGEN_DATA);

// Sign: seed, message and salt in, SHA3-256(signature) out; the kernel consumes the salt.
#define UOV_SIGN_DATA(field, string) \
    field(parameter_set, uint32_t) \
    field(sk_seed, uint8_t, UOV_CMD_MAX_SEED_BYTES) \
    field(sk_seed_len, size_t) \
    field(message, uint8_t, UOV_CMD_MAX_MSG_BYTES) \
    field(message_len, size_t) \
    field(salt, uint8_t, UOV_CMD_MAX_SALT_BYTES) \
    field(salt_len, size_t)
UJSON_SERDE_STRUCT(CryptotestUovSignData, cryptotest_uov_sign_data_t, UOV_SIGN_DATA);

// Verify: header first, then ceil(pk_len / UOV_CMD_MAX_PK_CHUNK_BYTES) chunks.
#define UOV_VERIFY_DATA(field, string) \
    field(parameter_set, uint32_t) \
    field(message, uint8_t, UOV_CMD_MAX_MSG_BYTES) \
    field(message_len, size_t) \
    field(signature, uint8_t, UOV_CMD_MAX_SIG_BYTES) \
    field(signature_len, size_t) \
    field(pk_len, size_t)
UJSON_SERDE_STRUCT(CryptotestUovVerifyData, cryptotest_uov_verify_data_t, UOV_VERIFY_DATA);

#define UOV_PK_CHUNK(field, string) \
    field(data, uint8_t, UOV_CMD_MAX_PK_CHUNK_BYTES) \
    field(len, size_t)
UJSON_SERDE_STRUCT(CryptotestUovPkChunk, cryptotest_uov_pk_chunk_t, UOV_PK_CHUNK);

// keygen/sign hash the output; verify leaves it zero and reports via `success`.
#define UOV_OUTPUT(field, string) \
    field(hash, uint8_t, UOV_CMD_HASH_BYTES) \
    field(success, bool)
UJSON_SERDE_STRUCT(CryptotestUovOutput, cryptotest_uov_output_t, UOV_OUTPUT);

#undef MODULE_ID

// clang-format on

#ifdef __cplusplus
}
#endif
#endif  // OPENTITAN_SW_DEVICE_TESTS_CRYPTO_CRYPTOTEST_JSON_UOV_COMMANDS_H_
