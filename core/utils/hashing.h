// Copyright (c) 2019, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_UTILS_HASHING_H_
#define BESS_UTILS_HASHING_H_

#include <glog/logging.h>
#include <x86intrin.h>

#include <rte_config.h>
#include <rte_hash_crc.h>

#include "common.h"

namespace bess {
namespace utils {

static inline uint32_t hash_16(uint16_t val, uint32_t init_val) {
#if __x86_64
  return crc32c_sse42_u16(val, init_val);
#else
  return crc32c_2bytes(val, init_val);
#endif
}

static inline uint32_t hash_32(uint32_t val, uint32_t init_val) {
#if __x86_64
  return crc32c_sse42_u32(val, init_val);
#else
  return crc32c_1word(val, init_val);
#endif
}

/* Returns a value in [0, range) as a function of an opaque number.
 * Also see utils/random.h */
static inline uint16_t hash_range(uint32_t hashval, uint16_t range) {
#if 1
  union {
    uint64_t i;
    double d;
  } tmp;

  /* the resulting number is 1.(b0)(b1)..(b31)00000..00 */
  tmp.i = 0x3ff0000000000000ull | (static_cast<uint64_t>(hashval) << 20);

  return (tmp.d - 1.0) * range;
#else
  /* This IDIV instruction is significantly slower */
  return hashval % range;
#endif
}

static inline uint32_t HashPktL2(const bess::Packet *pkt) {
  uint16_t *parts = pkt->head_data<uint16_t *>();
  uint16_t sum = 0;
  for (int j = 0; j < 6; j++) {
    sum = hash_16(parts[j], sum);
  }
  return sum;
}

static inline uint32_t HashPktL3(const bess::Packet *pkt) {
  // TODO(melvin): currently this assumes untagged packets. break that
  // assumption.
  const int ip_offset = 14;
  char *head = pkt->head_data<char *>();
  uint32_t sum = 0;
  // src IP
  sum = hash_32(*(reinterpret_cast<uint32_t *>(head + ip_offset + 12)), 0);
  // dst IP
  return hash_32(*(reinterpret_cast<uint32_t *>(head + ip_offset + 16)), sum);
}

static inline uint32_t HashPktL4(const bess::Packet *pkt) {
  // TODO(melvin): currently this assumes untagged packets. break that
  // assumption.
  const int ip_offset = 14;
  char *head = pkt->head_data<char *>();
  // ip_offset + IHL
  uint32_t l4_offset =
      ip_offset +
      ((*(reinterpret_cast<uint8_t *>(head + ip_offset)) & 0x0F) << 2);
  uint32_t sum = 0;
  // src IP
  sum = hash_32(*(reinterpret_cast<uint32_t *>(head + ip_offset + 12)), sum);
  // dst IP
  sum = hash_32(*(reinterpret_cast<uint32_t *>(head + ip_offset + 16)), sum);
  // src port
  sum = hash_32(*(reinterpret_cast<uint16_t *>(head + l4_offset)), sum);
  // dst port
  sum = hash_32(*(reinterpret_cast<uint16_t *>(head + l4_offset + 2)), sum);
  // ip_proto
  return hash_32(*(reinterpret_cast<uint8_t *>(head + ip_offset + 9)), sum);
}

}  // namespace utils
}  // namespace bess

#endif  // BESS_UTILS_HASHING_H_
