#ifndef OPENTITAN_SW_DEVICE_TESTS_ACC_UOV_ACC_DMEM_COPY_H_
#define OPENTITAN_SW_DEVICE_TESTS_ACC_UOV_ACC_DMEM_COPY_H_

// Word copies to and from ACC DMEM: acc_testutils_{write,read}_data without the per-word memcpy.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hw/top/acc_regs.h"  // Generated.
#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_acc.h"
#include "sw/device/lib/testing/acc_testutils.h"

static inline status_t acc_dmem_write(const dif_acc_t *acc, size_t len, const void *src,
                                      uint32_t dest) {
  if (((uintptr_t)src | dest | len) & 3) {
    return acc_testutils_write_data(acc, len, src, dest);
  }
  TRY_CHECK(dest + len <= ACC_DMEM_SIZE_BYTES);
  volatile uint32_t *d =
      (volatile uint32_t *)((uintptr_t)acc->base_addr.base + ACC_DMEM_REG_OFFSET + dest);
  const uint32_t *s = (const uint32_t *)src;
  size_t n = len / 4;
  for (; n >= 4; n -= 4, s += 4, d += 4) {
    uint32_t a0 = s[0], a1 = s[1], a2 = s[2], a3 = s[3];
    d[0] = a0, d[1] = a1, d[2] = a2, d[3] = a3;
  }
  for (; n > 0; --n) {
    *d++ = *s++;
  }
  return OK_STATUS();
}

static inline status_t acc_dmem_read(const dif_acc_t *acc, size_t len, uint32_t src, void *dest) {
  if (((uintptr_t)dest | src | len) & 3) {
    return acc_testutils_read_data(acc, len, src, dest);
  }
  TRY_CHECK(src + len <= ACC_DMEM_SIZE_BYTES);
  const volatile uint32_t *s =
      (const volatile uint32_t *)((uintptr_t)acc->base_addr.base + ACC_DMEM_REG_OFFSET + src);
  uint32_t *d = (uint32_t *)dest;
  size_t n = len / 4;
  for (; n >= 4; n -= 4, s += 4, d += 4) {
    uint32_t a0 = s[0], a1 = s[1], a2 = s[2], a3 = s[3];
    d[0] = a0, d[1] = a1, d[2] = a2, d[3] = a3;
  }
  for (; n > 0; --n) {
    *d++ = *s++;
  }
  return OK_STATUS();
}

// Declares x_ram, a word buffer in RAM holding the first n bytes of x.
#define UOV_IN_RAM(x, n)               \
  static uint32_t x##_ram[(n) / 4];    \
  memcpy(x##_ram, x, sizeof(x##_ram))

#endif  // OPENTITAN_SW_DEVICE_TESTS_ACC_UOV_ACC_DMEM_COPY_H_
