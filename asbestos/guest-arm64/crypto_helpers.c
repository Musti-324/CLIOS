/*
 * ARM64 Cryptographic Extension Helper Functions
 *
 * These are software implementations of the ARMv8 crypto instructions.
 * They're called from the gadgets in crypto.S.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* SM4 S-box */
static const uint8_t sm4_sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

static inline uint64_t ror64(uint64_t x, unsigned n) {
    n &= 63;
    if (n == 0)
        return x;
    return (x >> n) | (x << (64 - n));
}

static inline uint32_t rol32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

/*
 * EOR3: bitwise XOR of three vectors
 * Vd = Vn ^ Vm ^ Va
 */
void eor3_helper(uint8_t *vd, uint8_t *vn, uint8_t *vm, uint8_t *va) {
    for (int i = 0; i < 16; i++) {
        vd[i] = vn[i] ^ vm[i] ^ va[i];
    }
}

/*
 * SM3PARTW1: SM3 message schedule update (part 1)
 */
void sm3partw1_helper(uint32_t *vd, uint32_t *vn, uint32_t *vm) {
    uint32_t t0 = vd[0] ^ vn[0];
    uint32_t t1 = vd[1] ^ vn[1];
    uint32_t t2 = vd[2] ^ vn[2];
    uint32_t t3 = vd[3] ^ vn[3];

    uint32_t r0 = t0 ^ rol32(vm[1], 15);
    uint32_t r1 = t1 ^ rol32(vm[2], 15);
    uint32_t r2 = t2 ^ rol32(vm[3], 15);
    uint32_t r3 = t3 ^ rol32(r0, 15);

    r0 = r0 ^ rol32(r0, 15) ^ rol32(r0, 23);
    r1 = r1 ^ rol32(r1, 15) ^ rol32(r1, 23);
    r2 = r2 ^ rol32(r2, 15) ^ rol32(r2, 23);
    r3 = r3 ^ rol32(r3, 15) ^ rol32(r3, 23);

    vd[0] = r0;
    vd[1] = r1;
    vd[2] = r2;
    vd[3] = r3;
}

static inline uint32_t sm4_sbox_sub(uint32_t x) {
    uint32_t y = 0;
    y |= (uint32_t)sm4_sbox[x & 0xff];
    y |= (uint32_t)sm4_sbox[(x >> 8) & 0xff] << 8;
    y |= (uint32_t)sm4_sbox[(x >> 16) & 0xff] << 16;
    y |= (uint32_t)sm4_sbox[(x >> 24) & 0xff] << 24;
    return y;
}

/*
 * SM4E: SM4 round (4 rounds at once on vector lanes)
 */
void sm4e_helper(uint32_t *vd, uint32_t *vn) {
    uint32_t r0 = vd[0];
    uint32_t r1 = vd[1];
    uint32_t r2 = vd[2];
    uint32_t r3 = vd[3];

    for (int i = 0; i < 4; i++) {
        uint32_t rk = vn[i];
        uint32_t x = r1 ^ r2 ^ r3 ^ rk;
        x = sm4_sbox_sub(x);
        x = x ^ rol32(x, 2) ^ rol32(x, 10) ^ rol32(x, 18) ^ rol32(x, 24);
        x ^= r0;
        r0 = r1;
        r1 = r2;
        r2 = r3;
        r3 = x;
    }

    vd[0] = r0;
    vd[1] = r1;
    vd[2] = r2;
    vd[3] = r3;
}

/*
 * SVE helpers (modeled as 128-bit vectors)
 */
void sve_eor_d_helper(uint64_t *vd, uint64_t *vn, uint64_t *vm) {
    vd[0] = vn[0] ^ vm[0];
    vd[1] = vn[1] ^ vm[1];
}

void sve_xar_d_helper(uint64_t *vd, uint64_t *vn, uint64_t *vm, uint32_t imm) {
    // XAR: Vd = ROR(Vn XOR Vm, imm) - XOR first, then rotate
    unsigned n = imm & 63;
    vd[0] = ror64(vn[0] ^ vm[0], n);
    vd[1] = ror64(vn[1] ^ vm[1], n);
}

/*
 * PMULL: Polynomial Multiply Long
 * Performs carry-less multiplication (used in GCM mode of AES)
 *
 * For size=0 (8-bit elements): multiplies 8 pairs of bytes
 * For size=3 (64-bit elements): multiplies one pair of 64-bit values
 */
static __uint128_t pmull64_full(uint64_t a, uint64_t b) {
    __uint128_t result = 0;
    for (int i = 0; i < 64; i++) {
        if (b & (1ULL << i)) {
            result ^= ((__uint128_t)a) << i;
        }
    }
    return result;
}

void pmull_helper(uint8_t *rd, uint8_t *rn, uint8_t *rm, uint32_t Q, uint32_t size) {
    if (size == 0) {
        // 8-bit polynomial multiply: 8 pairs of bytes -> 8 halfwords
        // Vd may alias either input; widening stores overwrite unread bytes.
        uint8_t source_n[8], source_m[8];
        memcpy(source_n, rn + (Q ? 8 : 0), sizeof(source_n));
        memcpy(source_m, rm + (Q ? 8 : 0), sizeof(source_m));
        uint16_t *dst = (uint16_t *)rd;

        for (int i = 0; i < 8; i++) {
            uint16_t a = source_n[i];
            uint16_t b = source_m[i];
            uint16_t result = 0;
            for (int j = 0; j < 8; j++) {
                if (b & (1 << j)) {
                    result ^= a << j;
                }
            }
            dst[i] = result;
        }
    } else if (size == 3) {
        // 64-bit polynomial multiply: 1 pair of 64-bit -> 128-bit
        uint64_t *src_n = (uint64_t *)rn;
        uint64_t *src_m = (uint64_t *)rm;
        __uint128_t *dst = (__uint128_t *)rd;

        uint64_t a = Q ? src_n[1] : src_n[0];
        uint64_t b = Q ? src_m[1] : src_m[0];

        *dst = pmull64_full(a, b);
    }
}

/*
 * TBL - Table lookup
 *
 * Each byte of the index vector (rm) is used as an index into the table
 * formed by concatenating 1-4 consecutive vector registers starting at rn.
 * If the index is out of range, 0 is written to the destination.
 *
 * len: 0=1 register (16 bytes), 1=2 regs (32 bytes), 2=3 regs (48 bytes), 3=4 regs (64 bytes)
 * Q: 0=8-byte operation, 1=16-byte operation
 */
void tbl_helper(uint8_t *rd, uint8_t *rn, uint8_t *rm, int len, int Q, uint8_t *fp_base) {
    int num_elements = Q ? 16 : 8;
    int table_size = (len + 1) * 16;  // 16, 32, 48, or 64 bytes

    uint8_t result[16];

    for (int i = 0; i < num_elements; i++) {
        uint8_t index = rm[i];
        if (index < table_size) {
            // Calculate which register and offset within that register
            int reg_offset = index / 16;
            int byte_offset = index % 16;
            // Handle register wrap-around (V31 + 1 = V0)
            uint8_t *table_reg = rn + (reg_offset * 16);
            // Check if we've wrapped around the register file
            // fp_base points to V0, so check if we've gone past V31
            if (table_reg >= fp_base + 32 * 16) {
                table_reg -= 32 * 16;  // Wrap to V0
            }
            result[i] = table_reg[byte_offset];
        } else {
            result[i] = 0;
        }
    }

    // Copy result to destination
    for (int i = 0; i < num_elements; i++) {
        rd[i] = result[i];
    }
    // Clear upper bytes if 8-byte operation
    if (!Q) {
        for (int i = 8; i < 16; i++) {
            rd[i] = 0;
        }
    }
}

/*
 * TBX - Table lookup with extend
 *
 * Same as TBL, but out-of-range indices preserve the original destination value
 * instead of being set to 0.
 */
void tbx_helper(uint8_t *rd, uint8_t *rn, uint8_t *rm, int len, int Q, uint8_t *fp_base) {
    int num_elements = Q ? 16 : 8;
    int table_size = (len + 1) * 16;

    uint8_t result[16];

    // Copy original destination first (for TBX, out-of-range keeps original)
    for (int i = 0; i < 16; i++) {
        result[i] = rd[i];
    }

    for (int i = 0; i < num_elements; i++) {
        uint8_t index = rm[i];
        if (index < table_size) {
            int reg_offset = index / 16;
            int byte_offset = index % 16;
            uint8_t *table_reg = rn + (reg_offset * 16);
            if (table_reg >= fp_base + 32 * 16) {
                table_reg -= 32 * 16;
            }
            result[i] = table_reg[byte_offset];
        }
        // For TBX, if index >= table_size, we keep the original rd[i]
    }

    // Copy result to destination
    for (int i = 0; i < num_elements; i++) {
        rd[i] = result[i];
    }
    if (!Q) {
        for (int i = 8; i < 16; i++) {
            rd[i] = 0;
        }
    }
}

/*
 * SHL immediate helper for 32-bit and 64-bit element sizes
 */
void shl_imm_helper(uint8_t *rd, uint8_t *rn, int shift, int esize, int Q) {
    if (esize == 2) {
        // 32-bit elements
        uint32_t *src = (uint32_t *)rn;
        uint32_t *dst = (uint32_t *)rd;
        int count = Q ? 4 : 2;
        for (int i = 0; i < count; i++) {
            dst[i] = src[i] << shift;
        }
        if (!Q) {
            dst[2] = 0;
            dst[3] = 0;
        }
    } else if (esize == 3) {
        // 64-bit elements
        uint64_t *src = (uint64_t *)rn;
        uint64_t *dst = (uint64_t *)rd;
        int count = Q ? 2 : 1;
        for (int i = 0; i < count; i++) {
            dst[i] = src[i] << shift;
        }
        if (!Q) {
            dst[1] = 0;
        }
    }
}

/*
 * USHR immediate helper - unsigned shift right
 */
void ushr_imm_helper(uint8_t *rd, uint8_t *rn, int shift, int esize, int Q) {
    if (esize == 0) {
        // 8-bit elements
        int count = Q ? 16 : 8;
        for (int i = 0; i < count; i++) {
            rd[i] = rn[i] >> shift;
        }
        if (!Q) {
            for (int i = 8; i < 16; i++) rd[i] = 0;
        }
    } else if (esize == 1) {
        // 16-bit elements
        uint16_t *src = (uint16_t *)rn;
        uint16_t *dst = (uint16_t *)rd;
        int count = Q ? 8 : 4;
        for (int i = 0; i < count; i++) {
            dst[i] = src[i] >> shift;
        }
        if (!Q) {
            for (int i = 4; i < 8; i++) dst[i] = 0;
        }
    } else if (esize == 2) {
        // 32-bit elements
        uint32_t *src = (uint32_t *)rn;
        uint32_t *dst = (uint32_t *)rd;
        int count = Q ? 4 : 2;
        for (int i = 0; i < count; i++) {
            dst[i] = src[i] >> shift;
        }
        if (!Q) {
            dst[2] = 0;
            dst[3] = 0;
        }
    } else if (esize == 3) {
        // 64-bit elements
        uint64_t *src = (uint64_t *)rn;
        uint64_t *dst = (uint64_t *)rd;
        int count = Q ? 2 : 1;
        for (int i = 0; i < count; i++) {
            dst[i] = src[i] >> shift;
        }
        if (!Q) {
            dst[1] = 0;
        }
    }
}

/*
 * SSHR immediate helper - signed shift right
 */
void sshr_imm_helper(uint8_t *rd, uint8_t *rn, int shift, int esize, int Q) {
    if (esize == 0) {
        // 8-bit signed elements
        int8_t *src = (int8_t *)rn;
        int8_t *dst = (int8_t *)rd;
        int count = Q ? 16 : 8;
        for (int i = 0; i < count; i++) {
            dst[i] = src[i] >> shift;
        }
        if (!Q) {
            for (int i = 8; i < 16; i++) ((uint8_t *)rd)[i] = 0;
        }
    } else if (esize == 1) {
        // 16-bit signed elements
        int16_t *src = (int16_t *)rn;
        int16_t *dst = (int16_t *)rd;
        int count = Q ? 8 : 4;
        for (int i = 0; i < count; i++) {
            dst[i] = src[i] >> shift;
        }
        if (!Q) {
            for (int i = 4; i < 8; i++) ((uint16_t *)rd)[i] = 0;
        }
    } else if (esize == 2) {
        // 32-bit signed elements
        int32_t *src = (int32_t *)rn;
        int32_t *dst = (int32_t *)rd;
        int count = Q ? 4 : 2;
        for (int i = 0; i < count; i++) {
            dst[i] = src[i] >> shift;
        }
        if (!Q) {
            ((uint32_t *)rd)[2] = 0;
            ((uint32_t *)rd)[3] = 0;
        }
    } else if (esize == 3) {
        // 64-bit signed elements
        int64_t *src = (int64_t *)rn;
        int64_t *dst = (int64_t *)rd;
        int count = Q ? 2 : 1;
        for (int i = 0; i < count; i++) {
            dst[i] = src[i] >> shift;
        }
        if (!Q) {
            ((uint64_t *)rd)[1] = 0;
        }
    }
}

/*
 * USRA (vector, immediate) - Unsigned Shift Right and Accumulate
 * rd = rd + (rn >> shift) (unsigned)
 */
void usra_imm_helper(uint8_t *rd, uint8_t *rn, int shift, int esize, int Q) {
    if (esize == 0) {
        // 8-bit elements
        int count = Q ? 16 : 8;
        for (int i = 0; i < count; i++) {
            rd[i] = rd[i] + (rn[i] >> shift);
        }
    } else if (esize == 1) {
        // 16-bit elements
        uint16_t *src = (uint16_t *)rn;
        uint16_t *dst = (uint16_t *)rd;
        int count = Q ? 8 : 4;
        for (int i = 0; i < count; i++) {
            dst[i] = dst[i] + (src[i] >> shift);
        }
    } else if (esize == 2) {
        // 32-bit elements
        uint32_t *src = (uint32_t *)rn;
        uint32_t *dst = (uint32_t *)rd;
        int count = Q ? 4 : 2;
        for (int i = 0; i < count; i++) {
            dst[i] = dst[i] + (src[i] >> shift);
        }
    } else if (esize == 3) {
        // 64-bit elements
        uint64_t *src = (uint64_t *)rn;
        uint64_t *dst = (uint64_t *)rd;
        int count = Q ? 2 : 1;
        for (int i = 0; i < count; i++) {
            dst[i] = dst[i] + (src[i] >> shift);
        }
    }
}

/*
 * SSRA (vector, immediate) - Signed Shift Right and Accumulate
 * rd = rd + (rn >> shift) (signed)
 */
void ssra_imm_helper(uint8_t *rd, uint8_t *rn, int shift, int esize, int Q) {
    if (esize == 0) {
        // 8-bit signed elements
        int8_t *src = (int8_t *)rn;
        int8_t *dst = (int8_t *)rd;
        int count = Q ? 16 : 8;
        for (int i = 0; i < count; i++) {
            dst[i] = dst[i] + (src[i] >> shift);
        }
    } else if (esize == 1) {
        // 16-bit signed elements
        int16_t *src = (int16_t *)rn;
        int16_t *dst = (int16_t *)rd;
        int count = Q ? 8 : 4;
        for (int i = 0; i < count; i++) {
            dst[i] = dst[i] + (src[i] >> shift);
        }
    } else if (esize == 2) {
        // 32-bit signed elements
        int32_t *src = (int32_t *)rn;
        int32_t *dst = (int32_t *)rd;
        int count = Q ? 4 : 2;
        for (int i = 0; i < count; i++) {
            dst[i] = dst[i] + (src[i] >> shift);
        }
    } else if (esize == 3) {
        // 64-bit signed elements
        int64_t *src = (int64_t *)rn;
        int64_t *dst = (int64_t *)rd;
        int count = Q ? 2 : 1;
        for (int i = 0; i < count; i++) {
            dst[i] = dst[i] + (src[i] >> shift);
        }
    }
}

/*
 * SRI (vector, immediate) - Shift Right and Insert
 * For each element: rd = (rd & ~mask) | ((rn >> shift) & mask)
 * where mask = (1 << (element_bits - shift)) - 1
 * i.e., the lower (element_bits - shift) bits are inserted from the shifted source
 */
void sri_imm_helper(uint8_t *rd, uint8_t *rn, int shift, int esize, int Q) {
    if (esize == 0) {
        // 8-bit elements
        int count = Q ? 16 : 8;
        uint8_t mask = (1 << (8 - shift)) - 1;  // Mask for inserted bits
        for (int i = 0; i < count; i++) {
            uint8_t shifted = rn[i] >> shift;
            rd[i] = (rd[i] & ~mask) | (shifted & mask);
        }
    } else if (esize == 1) {
        // 16-bit elements
        uint16_t *src = (uint16_t *)rn;
        uint16_t *dst = (uint16_t *)rd;
        int count = Q ? 8 : 4;
        uint16_t mask = (1 << (16 - shift)) - 1;
        for (int i = 0; i < count; i++) {
            uint16_t shifted = src[i] >> shift;
            dst[i] = (dst[i] & ~mask) | (shifted & mask);
        }
    } else if (esize == 2) {
        // 32-bit elements
        uint32_t *src = (uint32_t *)rn;
        uint32_t *dst = (uint32_t *)rd;
        int count = Q ? 4 : 2;
        uint32_t mask = (1UL << (32 - shift)) - 1;
        for (int i = 0; i < count; i++) {
            uint32_t shifted = src[i] >> shift;
            dst[i] = (dst[i] & ~mask) | (shifted & mask);
        }
    } else if (esize == 3) {
        // 64-bit elements
        uint64_t *src = (uint64_t *)rn;
        uint64_t *dst = (uint64_t *)rd;
        int count = Q ? 2 : 1;
        uint64_t mask = (1ULL << (64 - shift)) - 1;
        for (int i = 0; i < count; i++) {
            uint64_t shifted = src[i] >> shift;
            dst[i] = (dst[i] & ~mask) | (shifted & mask);
        }
    }
}

/*
 * SLI (vector, immediate) - Shift Left and Insert
 * For each element: rd = (rd & ~mask) | ((rn << shift) & mask)
 * where mask = ~((1 << shift) - 1)
 * i.e., the upper (element_bits - shift) bits are inserted from the shifted source
 */
void sli_imm_helper(uint8_t *rd, uint8_t *rn, int shift, int esize, int Q) {
    if (esize == 0) {
        // 8-bit elements
        int count = Q ? 16 : 8;
        uint8_t mask = ~((1 << shift) - 1);  // Mask for inserted bits (upper bits)
        for (int i = 0; i < count; i++) {
            uint8_t shifted = rn[i] << shift;
            rd[i] = (rd[i] & ~mask) | (shifted & mask);
        }
    } else if (esize == 1) {
        // 16-bit elements
        uint16_t *src = (uint16_t *)rn;
        uint16_t *dst = (uint16_t *)rd;
        int count = Q ? 8 : 4;
        uint16_t mask = ~((1 << shift) - 1);
        for (int i = 0; i < count; i++) {
            uint16_t shifted = src[i] << shift;
            dst[i] = (dst[i] & ~mask) | (shifted & mask);
        }
    } else if (esize == 2) {
        // 32-bit elements
        uint32_t *src = (uint32_t *)rn;
        uint32_t *dst = (uint32_t *)rd;
        int count = Q ? 4 : 2;
        uint32_t mask = ~((1UL << shift) - 1);
        for (int i = 0; i < count; i++) {
            uint32_t shifted = src[i] << shift;
            dst[i] = (dst[i] & ~mask) | (shifted & mask);
        }
    } else if (esize == 3) {
        // 64-bit elements
        uint64_t *src = (uint64_t *)rn;
        uint64_t *dst = (uint64_t *)rd;
        int count = Q ? 2 : 1;
        uint64_t mask = ~((1ULL << shift) - 1);
        for (int i = 0; i < count; i++) {
            uint64_t shifted = src[i] << shift;
            dst[i] = (dst[i] & ~mask) | (shifted & mask);
        }
    }
}
