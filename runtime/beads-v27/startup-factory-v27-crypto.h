#ifndef STARTUP_FACTORY_V27_CRYPTO_H
#define STARTUP_FACTORY_V27_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct sfv27_sha256_ctx {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char block[64];
    size_t block_length;
};

static inline uint32_t sfv27_rotr32(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32U - count));
}

static inline void sfv27_secure_zero(void *value, size_t length) {
    volatile unsigned char *cursor = (volatile unsigned char *)value;
    while (length > 0U) {
        *cursor++ = 0U;
        --length;
    }
}

static inline void sfv27_sha256_transform(
    struct sfv27_sha256_ctx *context, const unsigned char block[64]
) {
    static const uint32_t constants[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    uint32_t words[64];
    for (size_t index = 0U; index < 16U; ++index) {
        size_t at = index * 4U;
        words[index] = ((uint32_t)block[at] << 24U)
            | ((uint32_t)block[at + 1U] << 16U)
            | ((uint32_t)block[at + 2U] << 8U)
            | (uint32_t)block[at + 3U];
    }
    for (size_t index = 16U; index < 64U; ++index) {
        uint32_t left = words[index - 15U];
        uint32_t right = words[index - 2U];
        uint32_t sigma0 = sfv27_rotr32(left, 7U) ^ sfv27_rotr32(left, 18U) ^ (left >> 3U);
        uint32_t sigma1 = sfv27_rotr32(right, 17U) ^ sfv27_rotr32(right, 19U) ^ (right >> 10U);
        words[index] = words[index - 16U] + sigma0 + words[index - 7U] + sigma1;
    }
    uint32_t a=context->state[0],b=context->state[1],c=context->state[2],d=context->state[3];
    uint32_t e=context->state[4],f=context->state[5],g=context->state[6],h=context->state[7];
    for (size_t index = 0U; index < 64U; ++index) {
        uint32_t sum1=sfv27_rotr32(e,6U)^sfv27_rotr32(e,11U)^sfv27_rotr32(e,25U);
        uint32_t choice=(e&f)^((~e)&g);
        uint32_t temporary1=h+sum1+choice+constants[index]+words[index];
        uint32_t sum0=sfv27_rotr32(a,2U)^sfv27_rotr32(a,13U)^sfv27_rotr32(a,22U);
        uint32_t majority=(a&b)^(a&c)^(b&c);
        uint32_t temporary2=sum0+majority;
        h=g;g=f;f=e;e=d+temporary1;d=c;c=b;b=a;a=temporary1+temporary2;
    }
    context->state[0]+=a;context->state[1]+=b;context->state[2]+=c;context->state[3]+=d;
    context->state[4]+=e;context->state[5]+=f;context->state[6]+=g;context->state[7]+=h;
    sfv27_secure_zero(words, sizeof(words));
}

static inline void sfv27_sha256_init(struct sfv27_sha256_ctx *context) {
    static const uint32_t initial[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    memcpy(context->state, initial, sizeof(initial));
    context->bit_count = 0U;
    context->block_length = 0U;
}

static inline void sfv27_sha256_update(
    struct sfv27_sha256_ctx *context, const void *value, size_t length
) {
    const unsigned char *cursor = (const unsigned char *)value;
    while (length > 0U) {
        size_t space = 64U - context->block_length;
        size_t count = length < space ? length : space;
        memcpy(context->block + context->block_length, cursor, count);
        context->block_length += count;
        context->bit_count += (uint64_t)count * 8U;
        cursor += count;
        length -= count;
        if (context->block_length == 64U) {
            sfv27_sha256_transform(context, context->block);
            context->block_length = 0U;
        }
    }
}

static inline void sfv27_sha256_final(
    struct sfv27_sha256_ctx *context, unsigned char output[32]
) {
    context->block[context->block_length++] = 0x80U;
    if (context->block_length > 56U) {
        memset(context->block + context->block_length, 0, 64U - context->block_length);
        sfv27_sha256_transform(context, context->block);
        context->block_length = 0U;
    }
    memset(context->block + context->block_length, 0, 56U - context->block_length);
    for (size_t index = 0U; index < 8U; ++index) {
        context->block[63U - index] = (unsigned char)(context->bit_count >> (index * 8U));
    }
    sfv27_sha256_transform(context, context->block);
    for (size_t index = 0U; index < 8U; ++index) {
        output[index*4U]=(unsigned char)(context->state[index]>>24U);
        output[index*4U+1U]=(unsigned char)(context->state[index]>>16U);
        output[index*4U+2U]=(unsigned char)(context->state[index]>>8U);
        output[index*4U+3U]=(unsigned char)context->state[index];
    }
    sfv27_secure_zero(context, sizeof(*context));
}

static inline void sfv27_sha256(
    const void *value, size_t length, unsigned char output[32]
) {
    struct sfv27_sha256_ctx context;
    sfv27_sha256_init(&context);
    sfv27_sha256_update(&context, value, length);
    sfv27_sha256_final(&context, output);
}

static inline void sfv27_hmac_sha256(
    const unsigned char key[32], const void *domain, size_t domain_length,
    const void *value, size_t length, unsigned char output[32]
) {
    unsigned char inner_key[64], outer_key[64], inner[32];
    memset(inner_key, 0x36, sizeof(inner_key));
    memset(outer_key, 0x5c, sizeof(outer_key));
    for (size_t index = 0U; index < 32U; ++index) {
        inner_key[index] ^= key[index];
        outer_key[index] ^= key[index];
    }
    struct sfv27_sha256_ctx context;
    sfv27_sha256_init(&context);
    sfv27_sha256_update(&context, inner_key, sizeof(inner_key));
    sfv27_sha256_update(&context, domain, domain_length);
    sfv27_sha256_update(&context, value, length);
    sfv27_sha256_final(&context, inner);
    sfv27_sha256_init(&context);
    sfv27_sha256_update(&context, outer_key, sizeof(outer_key));
    sfv27_sha256_update(&context, inner, sizeof(inner));
    sfv27_sha256_final(&context, output);
    sfv27_secure_zero(inner_key, sizeof(inner_key));
    sfv27_secure_zero(outer_key, sizeof(outer_key));
    sfv27_secure_zero(inner, sizeof(inner));
}

static inline int sfv27_equal(const unsigned char *left, const unsigned char *right, size_t length) {
    unsigned char difference = 0U;
    for (size_t index = 0U; index < length; ++index) difference |= left[index] ^ right[index];
    return difference == 0U;
}

#endif
